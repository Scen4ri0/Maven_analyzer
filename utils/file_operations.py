import os
import requests
from utils.logging import log_info, log_error, log_warning


def download_file(url, timeout=10):
    """
    Downloads a file from a given URL and returns its content.
    Logs the status of the download.
    Raises an exception if the download fails.

    :param url: The URL to download the file from.
    :param timeout: The timeout for the request in seconds.
    :return: The content of the file as bytes.
    """
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Error downloading file from {url}: {e}")


def save_file(file_name, content):
    """
    Saves content to a file with the specified name.
    Logs the operation status.

    :param file_name: The name of the file to save.
    :param content: The content to write to the file.
    """
    try:
        with open(file_name, 'wb') as file:
            file.write(content)
    except Exception as e:
        raise RuntimeError(f"Error saving file {file_name}: {e}")


def delete_file(file_name):
    """
    Deletes a file if it exists. Logs the operation.

    :param file_name: The name of the file to delete.
    """
    try:
        if os.path.exists(file_name):
            os.remove(file_name)
    except Exception as e:
        raise RuntimeError(f"Error deleting file {file_name}: {e}")


def clean_up_files(prefix, extensions=None):
    """
    Cleans up temporary files based on a prefix and a list of extensions.
    Logs each deleted file.

    :param prefix: The prefix of the files to clean up (e.g., artifact name with version).
    :param extensions: A list of file extensions to clean up (e.g., ['jar', 'pom']).
    """
    if extensions is None:
        extensions = [
            'jar', 'jar.asc', 'aar', 'aar.asc',
            'pom', 'pom.asc', 'module', 'module.asc'
        ]

    for ext in extensions:
        file_name = f"{prefix}.{ext}"
        delete_file(file_name)


def is_file_present(file_name):
    """
    Checks if a file exists in the current directory.

    :param file_name: The name of the file to check.
    :return: True if the file exists, False otherwise.
    """
    exists = os.path.exists(file_name)
    return exists


def load_file_content(file_name):
    """
    Reads the content of a file if it exists. Logs the operation.

    :param file_name: The name of the file to read.
    :return: The content of the file as bytes, or None if the file does not exist.
    """
    try:
        if is_file_present(file_name):
            with open(file_name, 'rb') as file:
                content = file.read()
                return content
        return None
    except Exception as e:
        raise RuntimeError(f"Error reading file {file_name}: {e}")


def validate_file_content(file_name, expected_start=None):
    """
    Validates the content of a file by checking its starting bytes.

    :param file_name: The name of the file to validate.
    :param expected_start: The expected starting bytes of the file content (e.g., b'PK' for ZIP files).
    :return: True if the file content matches the expected start, False otherwise.
    """
    try:
        content = load_file_content(file_name)
        if content and expected_start and not content.startswith(expected_start):
            return False
        return True
    except Exception as e:
        raise RuntimeError(f"Error validating file {file_name}: {e}")

def check_signature_files(prefix, extensions=None):
    """
    Checks if signature files are present for a given artifact prefix.
    Logs if signatures are missing.

    :param prefix: The prefix of the files to check (e.g., artifact name with version).
    :param extensions: A list of signature-related extensions to check.
    :return: False if any signature file is missing, True otherwise.
    """
    if extensions is None:
        extensions = ['jar.asc', 'pom.asc', 'aar.asc', 'module.asc']

    missing_signatures = []
    for ext in extensions:
        file_name = f"{prefix}.{ext}"
        if not is_file_present(file_name):
            missing_signatures.append(file_name)

    return len(missing_signatures) == 0