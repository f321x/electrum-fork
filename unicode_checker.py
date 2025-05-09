#!/usr/bin/env python3
import json
import os

from typing import List, Generator, Tuple


WHITELIST_PATH = ".unicode_whitelist.json"
SCAN_PATH = "./electrum"  # Source directory to scan


class Whitelist:
    def __init__(self, whitelist: dict[str, List[str]]):
        self.whitelist = whitelist

    def is_character_whitelist(self, unicode_char_hex: str, file_path: str) -> bool:
        if not file_path in self.whitelist:
            return False
        return unicode_char_hex in self.whitelist[file_path]

    # load whitelist: filename -> list of hex Unicode characters
    @classmethod
    def from_json(cls, whitelist_path: str) -> "Whitelist":
        if os.path.exists(whitelist_path):
            with open(whitelist_path, "r", encoding="utf-8") as f:
                whitelist = json.load(f)
            return cls(whitelist)
        else:
            raise FileNotFoundError(f"No whitelist file '{whitelist_path}'")


def get_gitignore_items(directory: str) -> set[str]:
    """Returns a set of items from .gitignore file in the given directory"""
    gitignore_path = os.path.join(directory, ".gitignore")
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip() and not line.startswith("#")}
    return set()

# generator recursively returning interesting file paths to check starting from root directory
# ignores items of .gitignore file if present in root directory
def get_relevant_files(root_directory: str) -> Generator[str]:
    gitignore_items: set[str] = get_gitignore_items(root_directory)
    for dirpath, _, filenames in os.walk(root_directory):
        for filename in filenames:
            if filename.endswith(".py"):
                yield os.path.join(dirpath, filename)


def get_file_lines(file_path: str) -> Generator[Tuple[int, str]]:
    with open(file_path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f):
            yield line_number, line


def get_unicode_characters_from_line_hex(line: str) -> Generator[Tuple[str, str]]:
    """Returns tuple of hex encoded and Unicode character for each Unicode character in line"""
    for char in line:
        if ord(char) > 127:  # ASCII range
            yield hex(ord(char))[2:], char  # Convert to hex and remove '0x' prefix


def run(whitelist_path: str = WHITELIST_PATH, scan_path: str = SCAN_PATH) -> None:
    whitelist = Whitelist.from_json(whitelist_path)

    for file_path in get_relevant_files(scan_path):
        for line_number, line in get_file_lines(file_path):
            for unicode_char_hex, char in get_unicode_characters_from_line_hex(line):
                if not whitelist.is_character_whitelist(unicode_char_hex, file_path):
                    print(f"File: {file_path}, Line: {line_number + 1}, Char: {char}[{unicode_char_hex}]")


if __name__ == "__main__":
    run()
