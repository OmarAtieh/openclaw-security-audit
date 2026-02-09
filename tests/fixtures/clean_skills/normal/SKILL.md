---
name: weather
description: Get weather information
metadata:
  openclaw:
    emoji: 🌤️
    commands:
      - name: weather
        description: "Check weather for a location"
        usage: "/weather [city]"
---

# Weather Skill

Provides current weather information for any city.

## Usage

```
/weather London
/weather "New York"
```

## How it works

Uses the OpenWeatherMap API to fetch current conditions.

```python
# Example code (not executed by skill)
import requests
response = requests.get(f"https://api.openweathermap.org/data/2.5/weather?q={city}")
data = response.json()
```

## Configuration

No API key required for basic usage.
