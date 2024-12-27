import os
import aiohttp
from utils.logging import log_info, log_error, log_warning


async def download_file(url, timeout=10):
    """
    Downloads a file from a given URL and returns its content.
    Logs the status of the download.
    Raises an exception if the download fails.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    content = await response.read()
                    if not content:
                        raise RuntimeError(f"Empty file content from {url}")
                    return content
                elif response.status == 404:
                    raise RuntimeError(f"File not found: {url}")
                else:
                    raise RuntimeError(f"Failed to download file from {url}: Status {response.status}")
    except aiohttp.ClientError as e:
        raise RuntimeError(f"Client error downloading file from {url}: {e}")
    except Exception as e:
        raise



def save_file(file_name, content):
    """
    Saves content to a file with the specified name.
    Logs the operation status.
    """
    if not content:
        log_warning(f"[Save File] Attempted to save empty content to {file_name}")
        raise ValueError(f"Empty content provided for {file_name}")

    try:
        with open(file_name, 'wb') as file:
            file.write(content)
    except Exception as e:
        raise



def delete_file(file_name):
    """
    Deletes a file if it exists. Logs the operation.

    :param file_name: The name of the file to delete.
    """
    try:
        if os.path.exists(file_name):
            os.remove(file_name)
    except Exception as e:
        raise


def clean_up_files(prefix, extensions=None):
    """
    Cleans up temporary files based on a prefix and a list of extensions.
    Logs each deleted file.
    """
    if extensions is None:
        extensions = [
            'jar', 'jar.asc', 'aar', 'aar.asc',
            'pom', 'pom.asc', 'module', 'module.asc'
        ]

    for ext in extensions:
        file_name = f"{prefix}.{ext}"
        if is_file_present(file_name):
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
        raise


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
        raise


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
