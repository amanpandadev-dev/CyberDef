# GeoIP Setup Guide

## Download GeoLite2 Database (Free)

1. **Create MaxMind Account** (required for GeoLite2):
   - Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
   - Sign up for free account
   - Generate license key

2. **Download Database**:
   ```bash
   # Option A: Direct download (after login)
   curl -o GeoLite2-City.tar.gz \
     "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz"
   
   # Extract
   tar -xzf GeoLite2-City.tar.gz
   
   # Move to standard location
   sudo mkdir -p /usr/local/share/GeoIP
   sudo cp GeoLite2-City_*/GeoLite2-City.mmdb /usr/local/share/GeoIP/
   ```
   
   ```bash
   # Option B: Using geoipupdate (recommended for auto-updates)
   brew install geoipupdate  # macOS
   
   # Configure ~/.geoipupdate.conf
   AccountID YOUR_ACCOUNT_ID
   LicenseKey YOUR_LICENSE_KEY
   EditionIDs GeoLite2-City
   
   # Run update
   geoipupdate
   ```

3. **Verify Installation**:
   ```bash
   ls -lh /usr/local/share/GeoIP/GeoLite2-City.mmdb
   # Should show ~70MB file
   ```

## Alternative Locations

The service checks these paths automatically:
- `/usr/local/share/GeoIP/GeoLite2-City.mmdb`
- `/usr/share/GeoIP/GeoLite2-City.mmdb`
- `./data/GeoLite2-City.mmdb` (project local)
- `~/.local/share/GeoIP/GeoLite2-City.mmdb`

## Testing

```python
from enrichment import GeoIPEnrichmentService

geoip = GeoIPEnrichmentService()
# Check if loaded
print(f"GeoIP available: {geoip.reader is not None}")
```

## Production Recommendations

1. **Auto-Update**: Set up cron job for `geoipupdate` (weekly)
   ```cron
   0 2 * * 0 /usr/local/bin/geoipupdate
   ```

2. **Monitoring**: Alert if database is >30 days old

3. **Fallback**: System gracefully handles missing database (just disables enrichment)

## Privacy & Legal

- GeoLite2 is free but requires attribution
- Accuracy: ~95% country, ~80% city
- Updates: Weekly (recommended)
- License: Creative Commons Attribution-ShareAlike 4.0
