# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Web scraping utilities for CTF data collection.
"""

import time
import logging
from typing import Optional, Any
from contextlib import contextmanager

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from bs4 import BeautifulSoup
except ImportError:
    webdriver = None
    Options = None
    By = None
    WebDriverWait = None
    EC = None
    TimeoutException = None
    WebDriverException = None
    BeautifulSoup = None

from .config import DataCollectionConfig


logger = logging.getLogger(__name__)


class WebScraper:
    """Shared web scraping utility for CTF data collection."""
    
    def __init__(self, config: DataCollectionConfig = None):
        if webdriver is None:
            raise ImportError(
                "Selenium not installed. Install with: pip install selenium beautifulsoup4"
            )
        
        self.config = config or DataCollectionConfig()
        self._driver = None
    
    def setup_driver(self) -> webdriver.Chrome:
        """Setup and return a configured Chrome browser."""
        options = Options()
        
        # Add all configured options
        for option in self.config.CHROME_OPTIONS:
            options.add_argument(option)
        
        try:
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(self.config.PAGE_LOAD_TIMEOUT)
            return driver
        except Exception as e:
            logger.error(f"Failed to setup Chrome driver: {e}")
            raise
    
    @contextmanager
    def driver_context(self):
        """Context manager for driver lifecycle management."""
        driver = None
        try:
            driver = self.setup_driver()
            yield driver
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception as e:
                    logger.warning(f"Error closing driver: {e}")
    
    def get_page_source(self, url: str, wait_for_element: str = None) -> Optional[str]:
        """
        Get page source with optional element waiting.
        
        Args:
            url: URL to fetch
            wait_for_element: CSS selector to wait for before returning source
            
        Returns:
            Page source HTML or None if failed
        """
        with self.driver_context() as driver:
            try:
                driver.get(url)
                time.sleep(2)  # Basic wait for page load
                
                if wait_for_element:
                    WebDriverWait(driver, self.config.ELEMENT_WAIT_TIMEOUT).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, wait_for_element))
                    )
                
                return driver.page_source
                
            except TimeoutException:
                logger.warning(f"Timeout waiting for element {wait_for_element} on {url}")
                return driver.page_source  # Return what we have
            except WebDriverException as e:
                logger.error(f"WebDriver error fetching {url}: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error fetching {url}: {e}")
                return None
    
    def parse_html(self, html: str) -> BeautifulSoup:
        """Parse HTML with BeautifulSoup."""
        if BeautifulSoup is None:
            raise ImportError("BeautifulSoup not installed. Install with: pip install beautifulsoup4")
        return BeautifulSoup(html, 'html.parser')
    
    def get_parsed_page(self, url: str, wait_for_element: str = None) -> Optional[BeautifulSoup]:
        """
        Get and parse a web page.
        
        Args:
            url: URL to fetch and parse
            wait_for_element: CSS selector to wait for
            
        Returns:
            Parsed BeautifulSoup object or None if failed
        """
        html = self.get_page_source(url, wait_for_element)
        if html:
            return self.parse_html(html)
        return None
    
    def retry_request(self, func, *args, **kwargs) -> Any:
        """Retry a function with exponential backoff."""
        for attempt in range(self.config.RETRY_ATTEMPTS):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == self.config.RETRY_ATTEMPTS - 1:
                    logger.error(f"Final attempt failed: {e}")
                    raise
                else:
                    wait_time = self.config.RETRY_DELAY * (2 ** attempt)
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time) 