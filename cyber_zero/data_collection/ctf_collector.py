# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0

"""
CTF Data Collection Module

This module provides classes for collecting CTF task information and writeups
from CTFtime.org and other sources.
"""

import json
import os
import time
from datetime import datetime
from typing import List, Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup

from .config import DataCollectionConfig


class CTFTaskCollector:
    """Collects CTF task information from CTFtime.org"""
    
    def __init__(self, config: DataCollectionConfig):
        self.config = config
        self.driver = None
    
    def setup_driver(self):
        """Setup and return a headless Chrome browser"""
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--log-level=3")  # Suppress logs
        
        self.driver = webdriver.Chrome(options=options)
        return self.driver
    
    def close_driver(self):
        """Close the browser driver"""
        if self.driver:
            self.driver.quit()
            self.driver = None
    
    def get_ctf_tasks(self, event_id: str) -> List[Dict[str, Any]]:
        """Fetch tasks for a specific CTF event"""
        if not self.driver:
            self.setup_driver()
            
        url = f"https://ctftime.org/event/{event_id}/tasks/"
        
        # Load the page
        self.driver.get(url)
        
        # Wait for the page to load
        time.sleep(3)
        
        try:
            # Wait for table to be visible
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "table.table-striped"))
            )
        except Exception:
            return []
        
        # Get HTML content after JS rendering
        html = self.driver.page_source
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract task data
        tasks = []
        for row in soup.select('table.table-striped tbody tr'):
            cols = row.find_all('td')
            if len(cols) < 4:
                continue
            
            task_link = cols[0].find('a')
            if not task_link:
                continue
                
            task_name = task_link.text.strip()
            task_url = 'https://ctftime.org' + task_link['href']
            
            points = cols[1].text.strip()
            
            # Extract tags
            tags = [tag.text.strip() for tag in cols[2].select('.label')]
            
            # Extract writeups count
            writeups_count = cols[3].text.strip()
            
            tasks.append({
                'name': task_name,
                'url': task_url,
                'points': points,
                'tags': tags,
                'writeups_count': writeups_count,
            })
        
        return tasks
    
    def process_event(self, event: Dict[str, Any], output_dir: str) -> Optional[Dict[str, Any]]:
        """Process a single event with its own driver instance"""
        event_id = event.get('event_id')
        
        if not event_id:
            return None
            
        ctf_name = event.get('ctf_name', 'Unknown')
        year = event.get('year', 'Unknown')
        event_type = event.get('type', '')
        
        # Create event-specific output directory
        event_dir = os.path.join(output_dir, f"{ctf_name}_{year}_{event_type}".replace(' ', '_'))
        os.makedirs(event_dir, exist_ok=True)
        
        # Get tasks for this event
        tasks = self.get_ctf_tasks(event_id)
        
        if not tasks:
            return None
        
        # Save tasks to file
        tasks_file = os.path.join(event_dir, 'tasks.json')
        with open(tasks_file, 'w') as f:
            json.dump(tasks, f, indent=2)
        
        return {
            'ctf_name': ctf_name,
            'year': year,
            'type': event_type,
            'event_id': event_id,
            'tasks_count': len(tasks),
            'output_dir': event_dir,
            'tasks_file': tasks_file
        }
    
    def collect_all_tasks(self, events: List[Dict[str, Any]], output_dir: str, max_workers: int = 4) -> List[Dict[str, Any]]:
        """Collect tasks for multiple events using parallel processing"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all events for processing
            future_to_event = {
                executor.submit(self.process_event, event, output_dir): event 
                for event in events
            }
            
            # Process completed futures
            for future in tqdm(as_completed(future_to_event), total=len(events), desc="Processing CTF events"):
                event = future_to_event[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"Error processing event {event.get('ctf_name', 'Unknown')}: {e}")
        
        return results


class WriteupCollector:
    """Collects writeup information and content from CTF tasks"""
    
    def __init__(self, config: DataCollectionConfig):
        self.config = config
        self.driver = None
    
    def setup_driver(self):
        """Setup and return a headless Chrome browser"""
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--log-level=3")  # Suppress logs
        
        self.driver = webdriver.Chrome(options=options)
        return self.driver
    
    def close_driver(self):
        """Close the browser driver"""
        if self.driver:
            self.driver.quit()
            self.driver = None
    
    def get_writeup_info(self, task_url: str) -> List[Dict[str, Any]]:
        """Extract writeup information for a specific CTF task"""
        if not self.driver:
            self.setup_driver()
            
        try:
            # Navigate to the task page
            self.driver.get(task_url)
            
            # Wait for the page to load
            time.sleep(2)
            
            # Try to find the writeups table
            try:
                WebDriverWait(self.driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "table.table-striped"))
                )
            except Exception:
                # No writeups table found
                return []
            
            # Get HTML content
            soup = BeautifulSoup(self.driver.page_source, 'html.parser')
            
            # Extract writeups
            writeups = []
            writeups_table = soup.find('table', class_='table-striped')
            
            if writeups_table:
                for row in writeups_table.find_all('tr')[1:]:  # Skip header
                    cols = row.find_all('td')
                    if len(cols) < 3:
                        continue
                    
                    # Extract writeup URL
                    link_tag = cols[0].find('a')
                    writeup_url = "https://ctftime.org" + link_tag['href'] if link_tag else None
                    
                    # Extract rating
                    rating_div = cols[1].find('div', id='user_rating')
                    rating = rating_div.text.strip() if rating_div else 'not rated'
                    
                    # Extract author/team
                    author_team = cols[2].text.strip()
                    
                    writeups.append({
                        'writeup_url': writeup_url,
                        'rating': rating,
                        'author_team': author_team
                    })
            
            return writeups
        
        except Exception as e:
            print(f"Error fetching writeup info for {task_url}: {e}")
            return []
    
    def process_task(self, task: Dict[str, Any], ctf_name: str, year: str, output_dir: str) -> Optional[Dict[str, Any]]:
        """Process a single task to extract its writeup information"""
        task_url = task.get('url')
        task_name = task.get('name', 'unknown')
        
        if not task_url or not task_name:
            return None
        
        # Check if the task has writeups
        writeups_count = task.get('writeups_count', '0')
        if writeups_count == '0' or writeups_count == 0:
            return None
        
        # Create task-specific output directory
        task_dir = os.path.join(output_dir, f"{ctf_name}_{year}_{task_name}".replace(' ', '_').replace('/', '_'))
        os.makedirs(task_dir, exist_ok=True)
        
        # Get writeup information
        writeups = self.get_writeup_info(task_url)
        
        if not writeups:
            return None
        
        # Save writeup information
        writeups_file = os.path.join(task_dir, 'writeups.json')
        with open(writeups_file, 'w') as f:
            json.dump(writeups, f, indent=2)
        
        return {
            'task_name': task_name,
            'ctf_name': ctf_name,
            'year': year,
            'writeups_count': len(writeups),
            'output_dir': task_dir,
            'writeups_file': writeups_file
        }
    
    def collect_all_writeups(self, tasks: List[Dict[str, Any]], ctf_name: str, year: str, 
                           output_dir: str, max_workers: int = 4) -> List[Dict[str, Any]]:
        """Collect writeups for multiple tasks using parallel processing"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks for processing
            future_to_task = {
                executor.submit(self.process_task, task, ctf_name, year, output_dir): task 
                for task in tasks
            }
            
            # Process completed futures
            for future in tqdm(as_completed(future_to_task), total=len(tasks), desc="Processing tasks"):
                task = future_to_task[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"Error processing task {task.get('name', 'Unknown')}: {e}")
        
        return results
