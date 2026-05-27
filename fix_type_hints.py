#!/usr/bin/env python3
"""
Fix Python 3.10+ type hints to be compatible with Python 3.9
"""
import re
from pathlib import Path

def fix_file(filepath):
    """Fix type hints in a single file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        
        # Fix simple types: Optional[str] -> Optional[str]
        content = re.sub(r': (str|int|datetime|bool|float) \| None', r': Optional[\1]', content)
        
        # Fix Dict/List with | None: Optional[Dict[str, Any]] -> Optional[Dict[str, Any]]
        content = re.sub(r': (Dict\[[^\]]+\]|List\[[^\]]+\]) \| None', r': Optional[\1]', content)
        
        # Fix custom types with | None: Optional[IncidentStatus] -> Optional[IncidentStatus]
        content = re.sub(r': ([A-Z][a-zA-Z0-9_]*) \| None', r': Optional[\1]', content)
        
        # Fix Dict[str, X] -> Dict[str, X]
        content = re.sub(r'\bdict\[', r'Dict[', content)
        
        # Fix List[X] -> List[X]
        content = re.sub(r'\blist\[', r'List[', content)
        
        # Fix Set[X] -> Set[X]
        content = re.sub(r'\bset\[', r'Set[', content)
        
        # Fix Tuple[X, Y] -> Tuple[X, Y]
        content = re.sub(r'\btuple\[', r'Tuple[', content)
        
        # Add typing imports if Optional/Dict/List/Set/Tuple are used but not imported
        if content != original:
            # Check if we need to add imports
            needs_optional = 'Optional[' in content
            needs_dict = 'Dict[' in content
            needs_list = 'List[' in content
            needs_set = 'Set[' in content
            needs_tuple = 'Tuple[' in content
            
            # Find the typing import line
            typing_import_match = re.search(r'^from typing import (.+)$', content, re.MULTILINE)
            
            if typing_import_match:
                current_imports = set(imp.strip() for imp in typing_import_match.group(1).split(','))
                needed_imports = set()
                
                if needs_optional:
                    needed_imports.add('Optional')
                if needs_dict:
                    needed_imports.add('Dict')
                if needs_list:
                    needed_imports.add('List')
                if needs_set:
                    needed_imports.add('Set')
                if needs_tuple:
                    needed_imports.add('Tuple')
                
                # Add missing imports
                all_imports = sorted(current_imports | needed_imports)
                new_import_line = f"from typing import {', '.join(all_imports)}"
                content = content.replace(typing_import_match.group(0), new_import_line)
        
        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Fix all Python files in the project"""
    root = Path(__file__).parent
    fixed_count = 0
    
    for py_file in root.rglob('*.py'):
        # Skip virtual environments and __pycache__
        if 'venv' in str(py_file) or '__pycache__' in str(py_file) or '.git' in str(py_file):
            continue
        
        if fix_file(py_file):
            print(f"Fixed: {py_file.relative_to(root)}")
            fixed_count += 1
    
    print(f"\nTotal files fixed: {fixed_count}")

if __name__ == '__main__':
    main()
