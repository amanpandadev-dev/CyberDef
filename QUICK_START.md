# Quick Start - IP Exclusion from CSV

## ✅ What You Have

A working IP exclusion system that reads from `data/Zscalar_ip_ranges.csv`

## 📝 CSV Format (Single Column)

### **Option 1: With Header**
```csv
ip_range
45.249.218.12/32
201.151.143.169/32
2605:4300:2d00::/40
```

### **Option 2: Without Header**
```csv
45.249.218.12/32
201.151.143.169/32
2605:4300:2d00::/40
```

**Both work!** The code auto-detects headers.

## 🚀 How to Add Your 2000 IP Ranges

### **Method 1: Copy-Paste**
1. Open `data/Zscalar_ip_ranges.csv`
2. Paste your IP ranges (one per line)
3. Save
4. Restart backend: `python main.py`

### **Method 2: From Excel**
```python
import pandas as pd

# Read Excel (assuming IPs in column A)
df = pd.read_excel('your_file.xlsx', header=None)

# Save to CSV
df[0].to_csv('data/Zscalar_ip_ranges.csv', index=False, header=['ip_range'])
```

### **Method 3: Python Script**
```python
ip_ranges = ["45.249.218.12/32", "201.151.143.169/32", ...]

with open('data/Zscalar_ip_ranges.csv', 'w') as f:
    f.write('ip_range\n')
    for ip in ip_ranges:
        f.write(f'{ip}\n')
```

## ✅ Verify It Works

```bash
# Run test
python test_csv_simple.py

# Should see:
# ✅ Successfully loaded X ranges
# ✅ All 10 tests passed
```

## 📊 Check Logs

When you start the backend:
```
INFO: Loaded 2000 excluded IP ranges from CSV
```

## 🎯 That's It!

All IPs in the CSV are now excluded from threat detection! 🚀
