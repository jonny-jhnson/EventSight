"""EVTX file parsing module."""

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import WindowsEvent


def _parse_evtx_with_wevtutil(file_path: str, max_events: Optional[int] = None) -> list[WindowsEvent]:
    """
    Parse EVTX file using Windows' wevtutil command.

    Uses native Windows wevtutil.exe to export events as XML for parsing.
    """
    import subprocess
    import shutil

    path = Path(file_path)
    events = []

    # Build wevtutil command (use .exe for WSL compatibility)
    wevtutil = shutil.which('wevtutil') or shutil.which('wevtutil.exe') or 'wevtutil.exe'
    cmd = [wevtutil, 'qe', str(path), '/lf', '/f:xml']
    if max_events:
        cmd.extend(['/c:' + str(max_events)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            encoding='utf-8',
            errors='replace'
        )

        if result.returncode != 0:
            # wevtutil failed, return empty list
            return []

        # Parse the XML output - it's a series of <Event>...</Event> elements
        xml_content = result.stdout

        # Split into individual events
        event_pattern = re.compile(r'<Event[^>]*>.*?</Event>', re.DOTALL)

        for i, match in enumerate(event_pattern.finditer(xml_content)):
            if max_events and i >= max_events:
                break

            try:
                event = _parse_xml_record(match.group())
                if event:
                    events.append(event)
            except Exception as e:
                print(f"Warning: Failed to parse event {i}: {e}")
                continue

    except subprocess.TimeoutExpired:
        print("Warning: wevtutil timed out")
    except FileNotFoundError:
        # wevtutil not available (not on Windows)
        pass
    except Exception as e:
        print(f"Warning: wevtutil failed: {e}")

    return events


def parse_evtx_file(file_path: str, max_events: Optional[int] = None) -> list[WindowsEvent]:
    """
    Parse an EVTX file and return structured events.

    Uses Windows' native wevtutil.exe to parse EVTX files.

    Args:
        file_path: Path to the EVTX file
        max_events: Maximum number of events to parse (None for all)

    Returns:
        List of WindowsEvent objects

    Raises:
        FileNotFoundError: If the EVTX file doesn't exist
        ValueError: If the file is not an EVTX file
        RuntimeError: If wevtutil is not available or fails
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"EVTX file not found: {file_path}")

    if not path.suffix.lower() == '.evtx':
        raise ValueError(f"File must be an EVTX file: {file_path}")

    # Verify wevtutil is available
    import shutil
    wevtutil_path = shutil.which('wevtutil') or shutil.which('wevtutil.exe')
    if not wevtutil_path:
        raise RuntimeError(
            "wevtutil.exe not found. This tool requires Windows.\n"
            "If running in WSL, ensure Windows interop is enabled."
        )

    # Parse using wevtutil
    events = _parse_evtx_with_wevtutil(file_path, max_events)
    if not events:
        print("Warning: No events were parsed from the file")

    return events


def _parse_xml_record(xml_string: str) -> Optional[WindowsEvent]:
    """Parse an XML event record into a WindowsEvent."""
    try:
        # Handle namespace (both single and double quotes)
        xml_string = re.sub(r'\sxmlns=["\'][^"\']+["\']', '', xml_string, count=1)
        root = ET.fromstring(xml_string)
        
        system = root.find('System')
        if system is None:
            return None
        
        # Extract event ID
        event_id_elem = system.find('EventID')
        event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0
        
        # Extract timestamp
        time_created = system.find('TimeCreated')
        timestamp_str = time_created.get('SystemTime', '') if time_created is not None else ''
        try:
            timestamp_str = timestamp_str.replace('Z', '+00:00')
            timestamp = datetime.fromisoformat(timestamp_str)
        except (ValueError, AttributeError):
            timestamp = datetime.now()
        
        # Extract other System fields
        channel_elem = system.find('Channel')
        computer_elem = system.find('Computer')
        provider_elem = system.find('Provider')
        level_elem = system.find('Level')
        task_elem = system.find('Task')
        opcode_elem = system.find('Opcode')
        keywords_elem = system.find('Keywords')
        security_elem = system.find('Security')
        execution_elem = system.find('Execution')
        
        # Build event data from EventData or UserData
        event_specific_data = {}
        
        event_data_elem = root.find('EventData')
        if event_data_elem is not None:
            for data_elem in event_data_elem.findall('Data'):
                name = data_elem.get('Name', f'Data_{len(event_specific_data)}')
                value = data_elem.text or ''
                event_specific_data[name] = value
        
        user_data_elem = root.find('UserData')
        if user_data_elem is not None:
            event_specific_data.update(_parse_user_data(user_data_elem))
        
        # Extract execution info
        process_id = None
        thread_id = None
        if execution_elem is not None:
            pid = execution_elem.get('ProcessID')
            tid = execution_elem.get('ThreadID')
            if pid:
                process_id = int(pid)
            if tid:
                thread_id = int(tid)
        
        return WindowsEvent(
            timestamp=timestamp,
            event_id=event_id,
            channel=channel_elem.text or '' if channel_elem is not None else '',
            computer=computer_elem.text or '' if computer_elem is not None else '',
            provider=provider_elem.get('Name', '') if provider_elem is not None else '',
            level=int(level_elem.text) if level_elem is not None and level_elem.text else 0,
            task=int(task_elem.text) if task_elem is not None and task_elem.text else 0,
            opcode=int(opcode_elem.text) if opcode_elem is not None and opcode_elem.text else 0,
            keywords=keywords_elem.text or '' if keywords_elem is not None else '',
            user_sid=security_elem.get('UserID', '') if security_elem is not None else None,
            process_id=process_id,
            thread_id=thread_id,
            event_data=event_specific_data,
            raw_xml=xml_string
        )
        
    except Exception as e:
        print(f"Error parsing XML record: {e}")
        return None


def _parse_user_data(user_data_elem) -> dict:
    """Parse UserData section recursively."""
    result = {}
    for child in user_data_elem:
        if len(child) > 0:
            # Has children, recurse
            child_data = _parse_user_data(child)
            for key, value in child_data.items():
                result[f"{child.tag}_{key}"] = value
        else:
            result[child.tag] = child.text or ''
    return result


def events_to_summary(events: list[WindowsEvent]) -> str:
    """Create a summary of events for relevance matching."""
    # Collect unique characteristics
    event_ids = set()
    processes = set()
    providers = set()
    
    for event in events:
        event_ids.add(event.event_id)
        
        # Extract process-related fields
        for key in ['Image', 'ParentImage', 'SourceImage', 'TargetImage', 
                    'ProcessName', 'ParentProcessName', 'NewProcessName']:
            if key in event.event_data:
                val = event.event_data[key]
                if val:
                    # Extract just the filename
                    if '\\' in str(val):
                        val = str(val).split('\\')[-1]
                    processes.add(val.lower())
        
        providers.add(event.provider)
    
    summary_parts = [
        f"Event IDs: {', '.join(str(x) for x in sorted(event_ids)[:20])}",
        f"Processes: {', '.join(sorted(processes)[:20])}",
        f"Providers: {', '.join(sorted(providers)[:10])}"
    ]
    
    return '\n'.join(summary_parts)


def filter_events_by_id(events: list[WindowsEvent], event_ids: list[int]) -> list[WindowsEvent]:
    """Filter events to only include specified event IDs."""
    return [e for e in events if e.event_id in event_ids]


def filter_security_relevant_events(events: list[WindowsEvent]) -> list[WindowsEvent]:
    """Filter to events that are commonly security-relevant."""
    # Security-relevant event IDs
    relevant_ids = {
        # Security log
        4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4699, 4700, 4701, 4702,
        4703, 4719, 4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4729, 4730,
        4731, 4732, 4733, 4734, 4735, 4737, 4738, 4739, 4740, 4741, 4742, 4743,
        4756, 4757, 4767, 4768, 4769, 4770, 4771, 4776, 4778, 4779, 4797, 4798,
        4799, 4964, 5136, 5140, 5145, 5156, 5157,
        
        # Sysmon
        1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 
        22, 23, 24, 25, 26, 27, 28, 29,
        
        # PowerShell
        4103, 4104, 4105, 4106,
        
        # WMI
        5857, 5858, 5859, 5860, 5861,
        
        # Task Scheduler  
        106, 140, 141, 200, 201,
        
        # Windows Defender
        1006, 1007, 1008, 1009, 1010, 1116, 1117, 1118, 1119,
    }
    
    return [e for e in events if e.event_id in relevant_ids]
