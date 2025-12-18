"""
Custom EVTX parser that handles various EVTX file formats.

This parser is designed to work with EVTX files that python-evtx fails to parse,
including .NET Runtime logs and ETL-converted files.
"""

import struct
import xml.sax.saxutils
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from .models import WindowsEvent


# EVTX Constants
EVTX_SIGNATURE = b'ElfFile\x00'
CHUNK_SIGNATURE = b'ElfChnk\x00'
RECORD_SIGNATURE = 0x00002a2a
CHUNK_SIZE = 0x10000  # 64KB


# BinXml Token Types (low nibble)
class BinXmlToken:
    END_OF_STREAM = 0x00
    OPEN_START_ELEMENT = 0x01
    CLOSE_START_ELEMENT = 0x02
    CLOSE_EMPTY_ELEMENT = 0x03
    CLOSE_ELEMENT = 0x04
    VALUE = 0x05
    ATTRIBUTE = 0x06
    CDATA_SECTION = 0x07
    CHAR_REF = 0x08
    ENTITY_REF = 0x09
    PI_TARGET = 0x0a
    PI_DATA = 0x0b
    TEMPLATE_INSTANCE = 0x0c
    NORMAL_SUBSTITUTION = 0x0d
    OPTIONAL_SUBSTITUTION = 0x0e
    FRAGMENT_HEADER = 0x0f


# Value Types
class ValueType:
    NULL = 0x00
    STRING = 0x01
    ANSI_STRING = 0x02
    INT8 = 0x03
    UINT8 = 0x04
    INT16 = 0x05
    UINT16 = 0x06
    INT32 = 0x07
    UINT32 = 0x08
    INT64 = 0x09
    UINT64 = 0x0a
    FLOAT = 0x0b
    DOUBLE = 0x0c
    BOOLEAN = 0x0d
    BINARY = 0x0e
    GUID = 0x0f
    SIZE_T = 0x10
    FILETIME = 0x11
    SYSTEMTIME = 0x12
    SID = 0x13
    HEX_INT32 = 0x14
    HEX_INT64 = 0x15
    BINXML = 0x21


def escape_xml(s: str) -> str:
    """Escape string for XML."""
    return xml.sax.saxutils.escape(str(s))


def escape_xml_attr(s: str) -> str:
    """Escape string for XML attribute."""
    return xml.sax.saxutils.quoteattr(str(s))[1:-1]


class BinXmlParser:
    """Parser for Windows Binary XML format."""

    def __init__(self, data: bytes, chunk_data: bytes):
        self.data = data
        self.chunk_data = chunk_data
        self.pos = 0
        self.string_cache = {}
        self.substitutions = []

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            return 0
        val = self.data[self.pos]
        self.pos += 1
        return val

    def peek_byte(self) -> int:
        if self.pos >= len(self.data):
            return -1
        return self.data[self.pos]

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            result = self.data[self.pos:]
            self.pos = len(self.data)
            return result
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_word(self) -> int:
        data = self.read_bytes(2)
        return struct.unpack('<H', data.ljust(2, b'\x00'))[0]

    def read_dword(self) -> int:
        data = self.read_bytes(4)
        return struct.unpack('<I', data.ljust(4, b'\x00'))[0]

    def read_qword(self) -> int:
        data = self.read_bytes(8)
        return struct.unpack('<Q', data.ljust(8, b'\x00'))[0]

    def read_wstring(self, char_count: int) -> str:
        """Read UTF-16LE string."""
        data = self.read_bytes(char_count * 2)
        return data.decode('utf-16-le', errors='replace').rstrip('\x00')

    def read_name(self, inline_only: bool = False) -> str:
        """Read element/attribute name.

        Args:
            inline_only: If True, expect inline name format without offset check
        """
        if inline_only:
            # Inline string: hash(2) + length(2) + string_data(len*2) + null(2)
            self.read_word()  # hash
            str_len = self.read_word()
            name = self.read_wstring(str_len)
            self.read_word()  # null terminator
            return name

        # Names can be inline or from string table
        # Format: offset(4) - if 0, followed by inline string
        name_offset = self.read_dword()

        if name_offset == 0:
            # Inline string: hash(2) + length(2) + string_data(len*2) + null(2)
            self.read_word()  # hash
            str_len = self.read_word()
            name = self.read_wstring(str_len)
            self.read_word()  # null terminator
            return name
        else:
            # From string table in chunk
            return self._get_string_from_chunk(name_offset)

    def _get_string_from_chunk(self, offset: int) -> str:
        """Get string from chunk's string table."""
        if offset in self.string_cache:
            return self.string_cache[offset]

        if offset >= len(self.chunk_data) or offset < 0:
            return f"str_{offset:x}"

        try:
            # String table format: next_offset(4) + hash(2) + length(2) + data
            next_ofs = struct.unpack('<I', self.chunk_data[offset:offset+4])[0]
            str_len = struct.unpack('<H', self.chunk_data[offset+6:offset+8])[0]

            if str_len > 500 or str_len == 0:
                return f"str_{offset:x}"

            str_data = self.chunk_data[offset+8:offset+8+str_len*2]
            result = str_data.decode('utf-16-le', errors='replace').rstrip('\x00')
            self.string_cache[offset] = result
            return result
        except Exception:
            return f"str_{offset:x}"

    def parse_to_xml(self) -> str:
        """Parse BinXml and return XML string."""
        try:
            output = []

            # Fragment header (0x0F)
            if self.pos < len(self.data) and (self.data[self.pos] & 0x0f) == 0x0f:
                self.pos += 4  # token + major + minor + flags

            self._parse_content(output)
            return ''.join(output)
        except Exception as e:
            return f"<Error>{escape_xml(str(e))}</Error>"

    def _parse_content(self, output: list, stop_on_close: bool = False) -> bool:
        """Parse content elements."""
        while self.pos < len(self.data):
            token = self.peek_byte()
            if token < 0:
                return False

            token_type = token & 0x0f

            if token_type == BinXmlToken.END_OF_STREAM:
                self.pos += 1
                return False

            elif token_type == BinXmlToken.OPEN_START_ELEMENT:
                self._parse_element(output)

            elif token_type == BinXmlToken.CLOSE_ELEMENT:
                self.pos += 1
                return stop_on_close

            elif token_type == BinXmlToken.VALUE:
                self.pos += 1
                val = self._parse_value()
                output.append(escape_xml(val))

            elif token_type == BinXmlToken.TEMPLATE_INSTANCE:
                self._parse_template_instance(output)

            elif token_type == BinXmlToken.NORMAL_SUBSTITUTION:
                self.pos += 1
                sub_id = self.read_word()
                self.read_byte()  # type
                if sub_id < len(self.substitutions):
                    output.append(escape_xml(str(self.substitutions[sub_id])))

            elif token_type == BinXmlToken.OPTIONAL_SUBSTITUTION:
                self.pos += 1
                sub_id = self.read_word()
                self.read_byte()  # type
                if sub_id < len(self.substitutions) and self.substitutions[sub_id]:
                    output.append(escape_xml(str(self.substitutions[sub_id])))

            elif token_type in (BinXmlToken.CLOSE_START_ELEMENT, BinXmlToken.CLOSE_EMPTY_ELEMENT):
                self.pos += 1
                return stop_on_close

            else:
                self.pos += 1

        return False

    def _parse_element(self, output: list):
        """Parse an element."""
        token = self.read_byte()
        has_more = bool(token & 0x40)

        if has_more:
            self.read_word()  # dependency id
            self.read_word()  # unknown/reserved field

        self.read_dword()  # data size
        elem_name = self.read_name()

        # After name, there's an attribute section size (4 bytes)
        self.read_dword()  # attribute section size

        output.append(f"<{elem_name}")

        has_content = self._parse_attributes(output)

        if not has_content:
            output.append("/>\n")
            return

        output.append(">")
        self._parse_content(output, stop_on_close=True)
        output.append(f"</{elem_name}>\n")

    def _parse_attributes(self, output: list) -> bool:
        """Parse attributes. Returns True if element has content."""
        while self.pos < len(self.data):
            token = self.peek_byte()
            if token < 0:
                return False

            token_type = token & 0x0f

            if token_type == BinXmlToken.CLOSE_START_ELEMENT:
                self.pos += 1
                return True

            elif token_type == BinXmlToken.CLOSE_EMPTY_ELEMENT:
                self.pos += 1
                return False

            elif token_type == BinXmlToken.ATTRIBUTE:
                self.pos += 1
                has_more = bool(token & 0x40)

                if has_more:
                    self.read_word()  # dependency id
                    self.read_word()  # reserved

                attr_name = self.read_name()

                # Parse value
                value = ""
                if self.peek_byte() >= 0 and (self.peek_byte() & 0x0f) == BinXmlToken.VALUE:
                    self.pos += 1
                    value = self._parse_value()

                output.append(f' {attr_name}="{escape_xml_attr(value)}"')

            else:
                return True

        return False

    def _parse_value(self) -> str:
        """Parse a value."""
        value_type = self.read_byte()
        return self._read_typed_value(value_type)

    def _read_typed_value(self, vtype: int) -> str:
        """Read a typed value."""
        if vtype == ValueType.NULL:
            return ""

        elif vtype == ValueType.STRING:
            self.read_byte()  # string type marker
            str_len = self.read_word()
            return self.read_wstring(str_len)

        elif vtype == ValueType.ANSI_STRING:
            self.read_byte()
            str_len = self.read_word()
            return self.read_bytes(str_len).decode('ascii', errors='replace').rstrip('\x00')

        elif vtype in (ValueType.INT8, ValueType.UINT8):
            return str(self.read_byte())

        elif vtype in (ValueType.INT16, ValueType.UINT16):
            return str(self.read_word())

        elif vtype in (ValueType.INT32, ValueType.UINT32):
            return str(self.read_dword())

        elif vtype in (ValueType.INT64, ValueType.UINT64):
            return str(self.read_qword())

        elif vtype == ValueType.FLOAT:
            data = self.read_bytes(4)
            if len(data) == 4:
                return str(struct.unpack('<f', data)[0])
            return "0"

        elif vtype == ValueType.DOUBLE:
            data = self.read_bytes(8)
            if len(data) == 8:
                return str(struct.unpack('<d', data)[0])
            return "0"

        elif vtype == ValueType.BOOLEAN:
            return "true" if self.read_byte() else "false"

        elif vtype == ValueType.GUID:
            data = self.read_bytes(16)
            if len(data) == 16:
                d1 = struct.unpack('<I', data[0:4])[0]
                d2 = struct.unpack('<H', data[4:6])[0]
                d3 = struct.unpack('<H', data[6:8])[0]
                return f"{{{d1:08x}-{d2:04x}-{d3:04x}-{data[8:10].hex()}-{data[10:16].hex()}}}"
            return ""

        elif vtype == ValueType.FILETIME:
            ft = self.read_qword()
            return self._filetime_to_str(ft)

        elif vtype == ValueType.SYSTEMTIME:
            data = self.read_bytes(16)
            if len(data) >= 16:
                year, month, _, day = struct.unpack('<HHHH', data[0:8])
                hour, minute, second, ms = struct.unpack('<HHHH', data[8:16])
                return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}.{ms:03d}Z"
            return ""

        elif vtype == ValueType.SID:
            size = self.read_word()
            data = self.read_bytes(size)
            return self._parse_sid(data)

        elif vtype == ValueType.HEX_INT32:
            return f"0x{self.read_dword():X}"

        elif vtype == ValueType.HEX_INT64:
            return f"0x{self.read_qword():X}"

        elif vtype == ValueType.BINARY:
            size = self.read_word()
            return self.read_bytes(size).hex()

        elif vtype == ValueType.SIZE_T:
            return str(self.read_qword())

        elif vtype == ValueType.BINXML:
            size = self.read_word()
            nested = self.read_bytes(size)
            try:
                p = BinXmlParser(nested, self.chunk_data)
                return p.parse_to_xml()
            except Exception:
                return ""

        else:
            return f"[type:0x{vtype:02x}]"

    def _filetime_to_str(self, ft: int) -> str:
        """Convert FILETIME to ISO string."""
        if ft == 0:
            return ""
        try:
            epoch_diff = 116444736000000000
            if ft > epoch_diff:
                ts = (ft - epoch_diff) / 10000000.0
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                return dt.isoformat().replace('+00:00', 'Z')
        except Exception:
            pass
        return str(ft)

    def _parse_sid(self, data: bytes) -> str:
        """Parse Windows SID."""
        if len(data) < 8:
            return data.hex() if data else ""

        revision = data[0]
        sub_count = data[1]
        authority = struct.unpack('>Q', b'\x00\x00' + data[2:8])[0]

        parts = [f"S-{revision}-{authority}"]
        offset = 8
        for _ in range(sub_count):
            if offset + 4 > len(data):
                break
            parts.append(str(struct.unpack('<I', data[offset:offset+4])[0]))
            offset += 4

        return '-'.join(parts)

    def _parse_template_instance(self, output: list):
        """Parse template instance."""
        self.pos += 1  # token
        self.read_byte()  # unknown
        template_id = self.read_dword()
        template_offset = self.read_dword()

        # Read substitution count and descriptors
        num_subs = self.read_dword()

        if num_subs > 0 and num_subs < 1000:
            descriptors = []
            for _ in range(num_subs):
                if self.pos + 4 > len(self.data):
                    break
                sub_size = self.read_word()
                sub_type = self.read_byte()
                self.read_byte()  # padding
                descriptors.append((sub_type, sub_size))

            # Read substitution values
            self.substitutions = []
            for sub_type, sub_size in descriptors:
                if self.pos >= len(self.data):
                    self.substitutions.append("")
                    continue
                try:
                    if sub_size == 0:
                        self.substitutions.append("")
                    else:
                        start_pos = self.pos
                        val = self._read_typed_value(sub_type)
                        # Ensure we read exactly sub_size bytes
                        bytes_read = self.pos - start_pos
                        if bytes_read < sub_size:
                            self.read_bytes(sub_size - bytes_read)
                        self.substitutions.append(val)
                except Exception:
                    self.substitutions.append("")

        # Parse template definition to generate XML
        if template_offset > 0 and template_offset < len(self.chunk_data):
            try:
                self._parse_template_def(output, template_offset)
            except Exception:
                pass

    def _parse_template_def(self, output: list, offset: int):
        """Parse template definition from chunk."""
        # Template definition starts at offset in chunk
        # Format: next_offset(4) + template_id(4) + guid(16) + data_size(4) + template_data

        if offset + 28 > len(self.chunk_data):
            return

        # Skip header to get to template BinXml
        template_data_offset = offset + 24  # Skip next_offset + template_id + guid + size

        if template_data_offset >= len(self.chunk_data):
            return

        # Get data size
        data_size = struct.unpack('<I', self.chunk_data[offset+20:offset+24])[0]

        if data_size > 0 and data_size < CHUNK_SIZE:
            template_data = self.chunk_data[template_data_offset:template_data_offset+data_size]

            # Parse template BinXml with substitutions
            saved_pos = self.pos
            saved_data = self.data

            self.data = template_data
            self.pos = 0

            try:
                self._parse_content(output)
            finally:
                self.data = saved_data
                self.pos = saved_pos


class EVTXParser:
    """Parser for Windows EVTX files."""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file = None
        self.file_header = None

    def __enter__(self):
        self.file = open(self.file_path, 'rb')
        self._read_file_header()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()

    def _read_file_header(self):
        """Read and validate EVTX file header."""
        self.file.seek(0)
        header = self.file.read(128)

        if header[:8] != EVTX_SIGNATURE:
            raise ValueError("Invalid EVTX file signature")

        self.file_header = {
            'oldest_chunk': struct.unpack('<Q', header[8:16])[0],
            'current_chunk_num': struct.unpack('<Q', header[16:24])[0],
            'next_record_num': struct.unpack('<Q', header[24:32])[0],
            'header_size': struct.unpack('<I', header[32:36])[0],
            'minor_version': struct.unpack('<H', header[36:38])[0],
            'major_version': struct.unpack('<H', header[38:40])[0],
            'header_chunk_size': struct.unpack('<H', header[40:42])[0],
            'chunk_count': struct.unpack('<H', header[42:44])[0],
        }

    def chunks(self) -> Iterator[bytes]:
        """Iterate over chunks."""
        chunk_offset = 0x1000
        self.file.seek(0, 2)
        file_size = self.file.tell()

        while chunk_offset + CHUNK_SIZE <= file_size:
            self.file.seek(chunk_offset)
            chunk_data = self.file.read(CHUNK_SIZE)

            if chunk_data[:8] == CHUNK_SIGNATURE:
                yield chunk_data

            chunk_offset += CHUNK_SIZE

    def records(self) -> Iterator[dict]:
        """Iterate over all records."""
        for chunk_data in self.chunks():
            yield from self._parse_chunk_records(chunk_data)

    def _parse_chunk_records(self, chunk_data: bytes) -> Iterator[dict]:
        """Parse records from a chunk."""
        free_space_offset = struct.unpack('<I', chunk_data[48:52])[0]
        record_offset = 0x200

        while record_offset < free_space_offset and record_offset < len(chunk_data) - 24:
            magic = struct.unpack('<I', chunk_data[record_offset:record_offset+4])[0]

            if magic != RECORD_SIGNATURE:
                record_offset += 8
                continue

            record_size = struct.unpack('<I', chunk_data[record_offset+4:record_offset+8])[0]
            record_num = struct.unpack('<Q', chunk_data[record_offset+8:record_offset+16])[0]
            timestamp = struct.unpack('<Q', chunk_data[record_offset+16:record_offset+24])[0]

            if record_size == 0 or record_size > CHUNK_SIZE:
                record_offset += 8
                continue

            # BinXml at offset 0x18
            binxml_start = record_offset + 0x18
            binxml_end = record_offset + record_size - 4
            binxml_data = chunk_data[binxml_start:binxml_end]

            try:
                parser = BinXmlParser(binxml_data, chunk_data)
                xml_string = parser.parse_to_xml()
            except Exception as e:
                xml_string = f"<Error>{escape_xml(str(e))}</Error>"

            yield {
                'record_num': record_num,
                'timestamp': timestamp,
                'xml': xml_string,
            }

            record_offset += record_size


def parse_evtx_file_custom(file_path: str, max_events: Optional[int] = None) -> list[WindowsEvent]:
    """Parse EVTX file using custom parser."""
    from .parser import _parse_xml_record

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"EVTX file not found: {file_path}")

    if path.suffix.lower() != '.evtx':
        raise ValueError(f"File must be an EVTX file: {file_path}")

    events = []

    with EVTXParser(str(path)) as parser:
        for i, record in enumerate(parser.records()):
            if max_events and i >= max_events:
                break

            try:
                xml_string = record.get('xml', '')
                if xml_string and not xml_string.startswith('<Error>'):
                    event = _parse_xml_record(xml_string)
                    if event:
                        events.append(event)
            except Exception as e:
                print(f"Warning: Failed to parse record {i}: {e}")
                continue

    return events
