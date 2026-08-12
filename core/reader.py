import gzip
from typing import Generator, Optional

def read_log_file(file_path: str, max_lines: Optional[int] = None) -> Generator[str, None, None]:
    """
    Reads a raw text or .gz log file line by line (Lazy Loading).
    Stops reading if max_lines limit is reached.
    """
    lines_read = 0
    
    open_func = gzip.open if file_path.endswith('.gz') else open

    try:
        with open_func(file_path, "rt", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if max_lines is not None and lines_read >= max_lines:
                    break
                
                cleaned_line = line.strip()
                if cleaned_line:  
                    yield cleaned_line
                    lines_read += 1
    except FileNotFoundError:
        print(f"\033[91m[ERROR] File not found: {file_path}\033[0m")
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to read file: {e}\033[0m")