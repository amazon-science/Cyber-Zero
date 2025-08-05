# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
import json
import argparse
from pathlib import Path
from markdownify import markdownify as md
import threading
import concurrent.futures
from tqdm import tqdm
import re
import html
from litellm import completion
# ANSI color codes for terminal output
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def call_by_litellm(messages, model_id, max_retries):
    for attempt in range(max_retries):
        try:
            response = completion(
                model=model_id,
                messages=messages,
            )['choices'][0]['message']['content']
            return response
        except Exception as e:
            print(f"Error on attempt {attempt + 1}: {e}")
    return None

def clean_writeup(text):
    """
    Clean HTML content and convert it to proper markdown using a two-step approach.
    
    Args:
        text (str): Text that may contain HTML
        
    Returns:
        str: Cleaned markdown text
    """
    if not text or not isinstance(text, str):
        return text
    
    # First, unescape HTML entities
    text = html.unescape(text)
    
    # Step 1: Convert HTML to markdown using html.parser (default)
    # Configure markdownify to handle various HTML elements properly
    md_text = md(text, 
                bs_parser='html.parser')  # Use html.parser first
    
    # Step 2: If there are still HTML tags, try with xml parser for more aggressive cleaning
    if '<' in md_text and '>' in md_text:
        try:
            md_text = md(md_text, 
                        bs_parser='xml')  # Use xml parser for second pass
        except Exception:
            # If xml parser fails, continue with the html.parser result
            pass
    
    # Clean up common markdown issues
    # Remove excessive whitespace
    md_text = re.sub(r'\n\s*\n\s*\n', '\n\n', md_text)
    
    # Fix empty code blocks
    md_text = re.sub(r'```\s*\n\s*```', '', md_text)
    
    # Fix multiple consecutive spaces
    md_text = re.sub(r' {3,}', '  ', md_text)
    
    # Remove trailing whitespace from lines
    md_text = '\n'.join(line.rstrip() for line in md_text.split('\n'))
    
    # Remove HTML tags that might have been missed
    md_text = re.sub(r'<[^>]+>', '', md_text)
    
    # Clean up remaining HTML entities
    md_text = re.sub(r'&[a-zA-Z]+;', lambda m: html.unescape(m.group(0)), md_text)
    md_text = re.sub(r'&#\d+;', lambda m: html.unescape(m.group(0)), md_text)
    md_text = re.sub(r'&#x[0-9a-fA-F]+;', lambda m: html.unescape(m.group(0)), md_text)
    
    # Remove excessive newlines at start and end
    md_text = md_text.strip()
    
    return md_text

def extract_competition_name(writeup_path):
    """Extract competition name from writeup path.
    
    Assumes the path structure contains the competition name as one of the directory components.
    This function attempts to extract a meaningful competition name from the path.
    """
    path_obj = Path(writeup_path)
    parts = path_obj.parts
    
    return parts[1]

def remove_urls(text):
    """
    Remove URLs from text using regex patterns.
    
    Args:
        text (str): Text that may contain URLs
        
    Returns:
        str: Text with URLs removed
    """
    if not text or not isinstance(text, str):
        return text
    
    # Remove various URL patterns
    # HTTP/HTTPS URLs
    text = re.sub(r'https?://[^\s\])\}\>]+', '', text)
    
    return text.strip()

PROMPT_TEMPLATE = '''You are given the following CTF challenge meta information and writeup. Extract the following fields and return ONLY a JSON object in a markdown code block:
- `task_tag` (string): One of "crypto", "forensics", "rev", "web", "pwn", or "misc"
- `task_name` (string)
- `task_points` (number, 0~1000): The points of the task are used to determine the difficulty of the task.
- `task_description` (string): The description of the task. You MUST make sure that the description provides enough information to be solved.
- `task_files` (list of strings): The paths of files that are highly likely to be included in the challenge based on the writeup. You MUST not include the flag file in this list, unless the writeup mentions it is available in the challenge.
- `server_description` (string): Information about connecting to servers in the template of "The challenge web server is running on `<server_ip>` port `<server_port>` and you can access it from within the container environment using `connect_start <server_ip> <server_port>`". (if applicable, you MUST follow this template, otherwise empty string). If the task contains a website, you must provide the description of a server, even if the writeup did not specify it.
- `solution` (string): The flag of the task. If there is no flag mentioned in the writeup, you MUST create a reasonable flag based on the description of the task and writeup.

Writeup:
{writeup_text}
'''

def process_trajectory(obj, model_id, max_retries, output_path, write_lock, verbose=False, demo=False):

    writeup_text = obj.get('task_writeup', '')
    writeup_path = obj.get('writeup_path', '')

    prompt = PROMPT_TEMPLATE.format(
        writeup_text=writeup_text
    )
    messages = [
        {"role": "system", "content": "You are an expert on extracting structured information from CTF writeups. You MUST make sure that the information inside the JSON object you return can be used to fully reproduce the setup of the CTF challenge. IF YOU CANNOT DETERMINE THE TASK FILES AND SERVER DESCRIPTION, YOU MUST MAKE SURE THE TASK DESCRIPTION PROVIDES ENOUGH INFORMATION TO BE SOLVED."},
        {"role": "user", "content": prompt}
    ]

    for attempt in range(max_retries):
        try:
            if demo:
                print(f"{YELLOW}Attempt {attempt+1}: Calling LLM...{RESET}")
            new_content = call_by_litellm(messages, model_id=model_id, max_retries=max_retries)
            if demo:
                print(f"{YELLOW}Received response from LLM. Parsing...{RESET}")
            match = re.search(r"```(?:json)?\n([\s\S]*?)\n```", new_content)
            if match:
                json_content = match.group(1)
                try:
                    json_obj = dict()
                    # Add writeup_path and competition_name
                    json_obj['competition_name'] = extract_competition_name(writeup_path)
                    json_obj.update(json.loads(json_content))
                    json_obj['task_writeup'] = writeup_text
                    json_obj['writeup_path'] = writeup_path
                    
                    if json_obj['solution'] == '':
                        return False
                    
                    # Validate required fields
                    required_fields = ['task_name', 'task_tag', 'task_points', 'task_description', 'task_files', 'server_description']
                    if not all(field in json_obj for field in required_fields):
                        if verbose or demo:
                            print(f"{RED}Attempt {attempt+1}: Missing required fields in JSON for {writeup_path}{RESET}")
                        continue
                    
                    # Validate task_tag value
                    valid_task_tags = ["crypto", "forensics", "rev", "web", "pwn", "misc"]
                    if json_obj['task_tag'] not in valid_task_tags:
                        if verbose or demo:
                            print(f"{RED}Attempt {attempt+1}: Invalid task_tag '{json_obj['task_tag']}' for {writeup_path}. Must be one of {valid_task_tags}{RESET}")
                        continue
                    
                    with write_lock:
                        with open(output_path, 'a', encoding='utf-8') as out:
                            out.write(json.dumps(json_obj, ensure_ascii=False) + '\n')
                    if demo:
                        print(f"{YELLOW}Output JSON:{RESET}\n{json.dumps(json_obj, ensure_ascii=False, indent=2)}")
                    return True
                except json.JSONDecodeError:
                    if verbose or demo:
                        print(f"{RED}Attempt {attempt+1}: Invalid JSON format for {writeup_path}{RESET}")
                    continue
            else:
                if verbose or demo:
                    print(f"{RED}Attempt {attempt+1}: No markdown code block detected for {writeup_path}{RESET}")
        except Exception as e:
            if verbose or demo:
                print(f"{RED}LLM error for {writeup_path}: {e}{RESET}")
            if attempt == max_retries - 1:
                return False
    if verbose or demo:
        print(f"{RED}Failed to get valid JSON response after {max_retries} attempts for {writeup_path}{RESET}")
    return False

def main():
    parser = argparse.ArgumentParser(description="Extract meta info from CTF writeups using LLM.")
    parser.add_argument('--input_path', default='writeups.txt', help='Input TXT file with writeup paths (one per line).')
    parser.add_argument('--output_path', default='task_meta_writeups.jsonl', help='Output JSONL file for processed meta info.')
    parser.add_argument('--workers', type=int, default=64, help='Number of parallel workers.')
    parser.add_argument('--overwrite', action='store_true', help='Overwrite output file.')
    parser.add_argument('--model_id', default='deepseek-v3-0324', help='Model ID for LLM rewriting.')
    parser.add_argument('--max_retries', type=int, default=20, help='Max retries for LLM.')
    parser.add_argument('--verbose', action='store_true', help='Verbose output.')
    parser.add_argument('--demo', action='store_true', help='Run in demo mode (process only one example with detailed output).')
    parser.add_argument('--part', type=int, choices=[1, 2, 3], help='Process only part 1, 2, or 3 of the data (splits data into 3 equal parts).')
    args = parser.parse_args()

    write_lock = threading.Lock()

    if args.overwrite:
        open(args.output_path, 'w').close()

    # Read writeup paths from TXT file
    writeup_paths = []
    with open(args.input_path, 'r', encoding='utf-8') as f:
        for line in f:
            path = line.strip()
            if path:
                writeup_paths.append(path)

    # Create objects from writeup paths
    objs = []
    skipped_count = 0
    for path in writeup_paths:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                # Clean the writeup and remove URLs
                writeup_text = clean_writeup(json.load(f)['markdown'])
                writeup_text = remove_urls(writeup_text)
                
                # Skip if text is less than 1000 characters after URL removal
                if len(writeup_text) < 1000:
                    skipped_count += 1
                    if args.verbose:
                        print(f"{YELLOW}Skipping {path}: text too short after URL removal ({len(writeup_text)} chars){RESET}")
                    continue
                    
            objs.append({
                'task_writeup': writeup_text,
                'writeup_path': path,
                'competition_name': extract_competition_name(path),
                'solution': ''  # Solution field is empty initially
            })
        except Exception as e:
            print(f"{RED}Error reading writeup from {path}: {e}{RESET}")

    print(f"{YELLOW}Skipped {skipped_count} samples due to insufficient length after URL removal{RESET}")

    # Split data into parts if --part is specified
    if args.part is not None:
        total_items = len(objs)
        part_size = total_items // 3
        remainder = total_items % 3
        
        if args.part == 1:
            start_idx = 0
            end_idx = part_size + (1 if remainder > 0 else 0)
        elif args.part == 2:
            start_idx = part_size + (1 if remainder > 0 else 0)
            end_idx = start_idx + part_size + (1 if remainder > 1 else 0)
        else:  # part == 3
            start_idx = 2 * part_size + (2 if remainder > 1 else (1 if remainder > 0 else 0))
            end_idx = total_items
            
        objs = objs[start_idx:end_idx]
        print(f"{YELLOW}Processing part {args.part}: items {start_idx}-{end_idx-1} ({len(objs)} items){RESET}")

    if args.demo:
        if objs:
            print(f"{YELLOW}Running in demo mode. Processing first example...{RESET}")
            process_trajectory(objs[0], args.model_id, args.max_retries, args.output_path, write_lock, verbose=True, demo=True)
        else:
            print(f"{RED}No examples found in input file.{RESET}")
        return

    existing_writeup_paths = set()
    if not args.overwrite and Path(args.output_path).exists():
        with open(args.output_path, 'r', encoding='utf-8') as out:
            for line in out:
                try:
                    obj = json.loads(line)
                    if 'writeup_path' in obj:
                        existing_writeup_paths.add(obj['writeup_path'])
                except Exception:
                    continue

    if not args.overwrite:
        objs = [obj for obj in objs if obj.get('writeup_path') not in existing_writeup_paths]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        with tqdm(total=len(objs), desc="Extracting meta info") as pbar:
            futures = []
            for obj in objs:
                futures.append(executor.submit(
                    process_trajectory, obj, args.model_id, args.max_retries, args.output_path, write_lock, args.verbose
                ))
            processed_count = 0
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    processed_count += 1
                pbar.update(1)
    print(f"Processed {processed_count} writeups.")

if __name__ == "__main__":
    main() 