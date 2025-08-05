# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Configuration for data collection utilities.
"""

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class DataCollectionConfig:
    """Configuration for CTF data collection."""
    
    # Web scraping settings
    SELENIUM_HEADLESS: bool = True
    PAGE_LOAD_TIMEOUT: int = 10
    ELEMENT_WAIT_TIMEOUT: int = 10
    RETRY_ATTEMPTS: int = 3
    RETRY_DELAY: float = 2.0
    
    # CTFtime.org settings
    CTFTIME_BASE_URL: str = "https://ctftime.org"
    TASKS_URL_TEMPLATE: str = "https://ctftime.org/event/{event_id}/tasks/"
    
    # Parallel processing
    MAX_WORKERS: int = 5
    BATCH_SIZE: int = 10
    
    # Output settings
    OUTPUT_DIR: str = "collected_data"
    JSON_INDENT: int = 2
    
    # Browser settings
    CHROME_OPTIONS: List[str] = None
    
    def __post_init__(self):
        if self.CHROME_OPTIONS is None:
            self.CHROME_OPTIONS = [
                "--headless",
                "--disable-gpu", 
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--log-level=3",
                "--disable-extensions",
                "--disable-dev-shm-usage",
                "--disable-background-timer-throttling",
                "--disable-backgrounding-occluded-windows",
                "--disable-renderer-backgrounding"
            ] 