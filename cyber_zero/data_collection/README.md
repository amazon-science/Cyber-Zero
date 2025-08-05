# Data Collection Utilities

This module provides utilities for collecting CTF data from various sources.

## Structure

```
cyber_zero/data_collection/
├── __init__.py              # Package initialization  
├── config.py               # Centralized configuration
└── scraper.py              # Shared web scraping utilities
```

## WebScraper

Shared utility for web scraping with configurable options:

```python
from cyber_zero.data_collection import WebScraper, DataCollectionConfig

config = DataCollectionConfig()
scraper = WebScraper(config)

# Get parsed page
soup = scraper.get_parsed_page("https://ctftime.org/event/12345/tasks/")
```

### Configuration
Centralized configuration for all data collection activities:

```python
from cyber_zero.data_collection import DataCollectionConfig

config = DataCollectionConfig()
config.MAX_WORKERS = 10
config.RETRY_ATTEMPTS = 5
```

## Dependencies

Optional dependencies for data collection:
```bash
pip install selenium beautifulsoup4 markdownify
```

## Future Development

The modular utilities provide a foundation for:
- Unified CLI interface
- Better error handling and logging
- Integration with main cyber-zero framework
- Comprehensive testing coverage 