import gzip
import sys
from typing import Generator, Optional

def read_log_stream(file_path: Optional[str] = None, max_lines: Optional[int] = None) -> Generator[str, None, None]:
    """
    Reads log lines lazily from standard input (STDIN) or from a file (.log, .txt, .gz).
    Stops processing when max_lines is reached.
    """
    lines_read = 0

    if file_path == "-" or (file_path is None and not sys.stdin.isatty()):
        try:
            for line in sys.stdin:
                if max_lines is not None and lines_read >= max_lines:
                    break
                cleaned = line.strip()
                if cleaned:
                    yield cleaned
                    lines_read += 1
        except KeyboardInterrupt:
            pass
        return

    if not file_path:
        print("\033[91m[ERROR] No file provided and no STDIN input detected.\033[0m")
        return

    open_func = gzip.open if file_path.endswith('.gz') else open

    try:
        with open_func(file_path, "rt", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if max_lines is not None and lines_read >= max_lines:
                    break
                cleaned = line.strip()
                if cleaned:
                    yield cleaned
                    lines_read += 1
    except FileNotFoundError:
        print(f"\033[91m[ERROR] File not found: {file_path}\033[0m")
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to read file: {e}\033[0m")