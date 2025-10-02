#!/usr/bin/env python3
import os
import csv
from collections import defaultdict

# Mapping file extensions to languages
EXT_LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".sh": "shell",
    ".html": "html",
    ".css": "css",
    # Add more as needed
}

def analyze_repo_languages(cloned_repo_path, csv_file_path=None):
    """
    Analyze files in a cloned repository and return:
      - percentage of files per language
      - full paths of files grouped by language
      - optional CSV record of files

    Args:
        cloned_repo_path (str): Path to the cloned repository folder
        csv_file_path (str, optional): Path to save CSV file. If None, CSV won't be created.

    Returns:
        language_percent (dict): {language: percentage_of_files}
        language_files (dict): {language: [list_of_file_paths]}
        csv_file_path (str or None): Path of created CSV file
    """
    if not os.path.exists(cloned_repo_path):
        raise FileNotFoundError(f"Path does not exist: {cloned_repo_path}")

    language_files = defaultdict(list)
    total_files = 0

    # Walk the repository
    for root, _, files in os.walk(cloned_repo_path):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            lang = EXT_LANG_MAP.get(ext)
            if lang:
                full_path = os.path.join(root, f)
                language_files[lang].append(full_path)
                total_files += 1

    # Calculate percentages
    language_percent = {}
    for lang, files in language_files.items():
        language_percent[lang] = round(len(files) / total_files * 100, 2)

    # Create CSV if path provided
    if csv_file_path:
        with open(csv_file_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Language", "File Path"])
            for lang, files in language_files.items():
                for fpath in files:
                    writer.writerow([lang, fpath])
        print(f"[✔] CSV file created at {csv_file_path}")

    return language_percent, dict(language_files), csv_file_path

def cleanup_csv(csv_file_path):
    """Delete CSV file if it exists."""
    if csv_file_path and os.path.exists(csv_file_path):
        os.remove(csv_file_path)
        print(f"[i] CSV file {csv_file_path} deleted.")
