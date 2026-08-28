#!/usr/bin/env python3
"""
Fix JSON formatting issues in syscall event logs.
Extracts raw_events section and corrects:
- Missing commas after fields
- Trailing commas before closing braces
- Empty string field handling
"""

import json
import re
import sys
from pathlib import Path

def fix_json_formatting(input_file, output_file, process_name=None, pids=None):
    """Fix JSON formatting issues and extract raw_events.

    Filtering is mutually exclusive: if `pids` is given, entries are kept
    when their "pid" is in `pids`; otherwise `process_name` is used to
    match the "process_name" field.
    """

    try:
        with open(input_file, 'r') as f:
            content = f.read()

        # Find the "raw_events" section
        raw_events_match = re.search(r'"raw_events"\s*:\s*\[', content)
        if not raw_events_match:
            print(f"Warning: 'raw_events' section not found in {input_file}")
            print("Attempting to parse entire file...")
            json_start = 0
        else:
            json_start = raw_events_match.start()
            # Find the opening bracket
            bracket_start = content.find('[', raw_events_match.start())
            json_start = bracket_start

        # Extract the JSON portion
        json_content = content[json_start:]

        # Find the end of the JSON array
        # Count brackets to find the matching closing bracket
        bracket_count = 0
        end_pos = 0
        in_string = False
        escape_next = False

        for i, char in enumerate(json_content):
            if escape_next:
                escape_next = False
                continue
            if char == '\\':
                escape_next = True
                continue
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
            if not in_string:
                if char == '[':
                    bracket_count += 1
                elif char == ']':
                    bracket_count -= 1
                    if bracket_count == 0:
                        end_pos = i + 1
                        break

        if end_pos == 0:
            json_content = content[json_start:]
        else:
            json_content = content[json_start:json_start + end_pos]

        # Fix JSON formatting issues
        lines = json_content.split('\n')
        fixed_lines = []

        for i, line in enumerate(lines):
            stripped = line.rstrip()

            # Skip empty lines
            if not stripped:
                fixed_lines.append(line)
                continue

            # Fix 1: Add comma after "offset": 0 (and similar number fields)
            if re.match(r'^\s*"offset":\s*\d+$', stripped):
                if i < len(lines) - 1 and lines[i + 1].strip().startswith('"'):
                    stripped += ','

            # Fix 2: Add comma after any field line that's missing it
            # if next line starts with a quote and contains a colon (new field)
            elif i < len(lines) - 1:
                next_line = lines[i + 1].strip()
                if (stripped.endswith('"') and not stripped.endswith(',') and 
                    next_line.startswith('"') and ':' in next_line and '{' not in next_line):
                    stripped += ','

            # Fix 3: Add comma after "open_flags_str" field
            if '"open_flags_str":' in stripped and not stripped.endswith(','):
                if i < len(lines) - 1:
                    next_line = lines[i + 1].strip()
                    # Add comma if next line is a field (starts with quote)
                    if next_line.startswith('"'):
                        stripped += ','

            # Fix 4: Remove trailing comma before closing brace
            if stripped.endswith(','):
                for j in range(i + 1, len(lines)):
                    next_non_empty = lines[j].strip()
                    if next_non_empty:
                        if next_non_empty in ('}', '},'):
                            # Remove trailing comma
                            stripped = stripped.rstrip(',').rstrip()
                        break

            fixed_lines.append(stripped)

        # Join and parse as JSON to validate
        fixed_json_str = '\n'.join(fixed_lines)

        try:
            # Try to parse as JSON to validate
            parsed = json.loads(fixed_json_str)
            print(f"✓ JSON validation successful")
            if isinstance(parsed, list):
                print(f"  Found {len(parsed)} syscall events")
                # Filter: keep only entries belonging to the requested process(es)
                if pids:
                    filtered = [entry for entry in parsed if entry.get("pid") in pids]
                    print(f"  After filtering for pids {sorted(pids)}: {len(filtered)} syscall events")
                elif process_name:
                    filtered = [entry for entry in parsed if entry.get("process_name") == process_name]
                    print(f"  After filtering for '{process_name}': {len(filtered)} syscall events")
                else:
                    filtered = parsed
                fixed_json_str = json.dumps(filtered, indent=2)
            else:
                print(f"  Parsed JSON structure")
        except json.JSONDecodeError as e:
            print(f"⚠ Warning: JSON validation failed: {e}")
            print(f"  Proceeding with best-effort fix (no fio filter applied)...")

        # Write to output file
        with open(output_file, 'w') as f:
            f.write(fixed_json_str)

        print(f"✓ Fixed JSON written to: {output_file}")

        # Print statistics
        input_size = len(content)
        output_size = len(fixed_json_str)
        print(f"\nStatistics:")
        print(f"  Original file size: {input_size:,} bytes")
        print(f"  Fixed JSON size: {output_size:,} bytes")
        print(f"  Reduction: {input_size - output_size:,} bytes")

        return True

    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 fix_json.py <input_file> [process_name | pid1,pid2,...]")
        print("\nExamples:")
        print("  python3 fix_json.py /home/user/sample_syscall_events.json")
        print("  python3 fix_json.py /home/user/sample_syscall_events.json fio")
        print("  python3 fix_json.py /home/user/sample_syscall_events.json 153047,153048,153049")
        print("  python3 fix_json.py /home/user/sample_syscall_events.json 153047 153048 153049")
        print("\nOutput will be created as: syscall_events_fixed.json in the same directory")
        sys.exit(1)

    input_file = sys.argv[1]
    process_name = None
    pids = None

    if len(sys.argv) >= 3:
        # Accept pids separated by commas and/or spaces across the remaining args
        tokens = [t for t in re.split(r'[,\s]+', ' '.join(sys.argv[2:])) if t]
        if tokens and all(t.isdigit() for t in tokens):
            pids = {int(t) for t in tokens}
        else:
            process_name = ' '.join(sys.argv[2:])

    # Generate output filename in the same directory as input
    input_path = Path(input_file)
    output_dir = input_path.parent
    output_file = output_dir / 'syscall_events_fixed.json'

    print(f"Fixing JSON formatting...")
    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    if pids:
        print(f"Filter: pid in {sorted(pids)}")
    elif process_name:
        print(f"Filter: process_name == '{process_name}'")
    print()

    if fix_json_formatting(str(input_file), str(output_file), process_name=process_name, pids=pids):
        print(f"\n✓ Done! You can now proceed to filter using filter_syscall_log.py")
        print(f"  Generated output file {output_file} ")
        sys.exit(0)
    else:
        sys.exit(1)
