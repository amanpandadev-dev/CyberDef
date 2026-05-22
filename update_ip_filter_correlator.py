#!/usr/bin/env python3
"""Update correlator to use centralized IP filter"""

def main():
    filepath = 'threat_state/correlator.py'
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace the import ipaddress check with centralized filter
    old_check = '''        import ipaddress
        
        # Only check public IPs
        try:
            is_public = not ipaddress.ip_address(actor.ip).is_private
        except ValueError:
            is_public = False
        
        if not is_public:
            return []'''
    
    new_check = '''        # Only check public IPs (uses centralized IP filter with custom exclusions)
        if is_ip_excluded(actor.ip):
            return []'''
    
    if old_check in content:
        content = content.replace(old_check, new_check)
        print("✅ Updated _check_rate_acceleration to use centralized IP filter")
    else:
        print("⚠️  Pattern not found in _check_rate_acceleration")
    
    # Also update _check_data_exfil
    old_exfil = '''        # Check if IP is public (interpreting dstip check against the actor's public address)
        try:
            is_public = not ipaddress.ip_address(actor.ip).is_private
        except ValueError:
            is_public = False'''
    
    new_exfil = '''        # Check if IP is public (uses centralized IP filter with custom exclusions)
        is_public = not is_ip_excluded(actor.ip)'''
    
    if old_exfil in content:
        content = content.replace(old_exfil, new_exfil)
        print("✅ Updated _check_data_exfil to use centralized IP filter")
    else:
        print("⚠️  Pattern not found in _check_data_exfil")
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("\n✅ Successfully updated threat_state/correlator.py")
    return 0

if __name__ == '__main__':
    exit(main())
