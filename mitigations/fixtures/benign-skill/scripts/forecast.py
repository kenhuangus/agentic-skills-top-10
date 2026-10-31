"""Fetch a forecast from Open-Meteo (illustrative fixture)."""
import json
import sys
import urllib.parse
import urllib.request

API = "https://api.open-meteo.com/v1/forecast"


def forecast(lat: float, lon: float) -> dict:
    q = urllib.parse.urlencode({"latitude": lat, "longitude": lon, "current_weather": "true"})
    with urllib.request.urlopen(f"{API}?{q}", timeout=10) as r:
        return json.load(r)


if __name__ == "__main__":
    print(json.dumps(forecast(float(sys.argv[1]), float(sys.argv[2]))))
