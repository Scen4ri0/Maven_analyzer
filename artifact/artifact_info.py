# artifact/artifact_info.py

from artifact.artifact_status import ArtifactStatus
from utils.logging import log_info, log_error, log_warning
import asyncio
import aiohttp
from xml.etree import ElementTree as ET
from datetime import datetime, timezone

async def extract_publication_date(base_repository_url, group_id, artifact_id, version):
    """
    Асинхронно извлекает дату публикации для конкретной версии из POM-файла или HTTP-заголовков.

    Args:
        base_repository_url (str): Базовый URL репозитория.
        group_id (str): Группа артефакта.
        artifact_id (str): Идентификатор артефакта.
        version (str): Версия артефакта.

    Returns:
        datetime: Дата публикации (если удалось определить), иначе None.
    """
    pom_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.pom"

    async with aiohttp.ClientSession() as session:
        try:
            # Попытка скачать POM-файл
            async with session.get(pom_url, timeout=10) as response:
                if response.status == 200:
                    pom_content = await response.text()
                    root = ET.fromstring(pom_content)
                    
                    # Попытка найти inceptionYear
                    inception_year = root.find(".//inceptionYear")
                    if inception_year is not None:
                        return datetime.strptime(inception_year.text.strip(), "%Y").replace(tzinfo=timezone.utc)

                    # Попытка найти releaseDate
                    release_date = root.find(".//releaseDate")
                    if release_date is not None:
                        return datetime.strptime(release_date.text.strip(), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                else:
                    log_warning(f"[Publication Date] Не удалось загрузить POM-файл: {pom_url} (Статус: {response.status})")
        except Exception as e:
            log_warning(f"[Publication Date] Ошибка при обработке POM-файла: {e}")

        # Если POM недоступен, используем HTTP-заголовок Last-Modified
        try:
            async with session.head(pom_url, timeout=10) as head_response:
                if head_response.status == 200:
                    last_modified = head_response.headers.get("Last-Modified")
                    if last_modified:
                        return datetime.strptime(last_modified, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
                else:
                    log_warning(f"[Publication Date] Не удалось получить заголовок Last-Modified: {pom_url}")
        except Exception as e:
            log_warning(f"[Publication Date] Ошибка при получении Last-Modified: {e}")

    return None  # Если все попытки не удались


async def get_selected_versions(base_repository_url, group_id, artifact_id, start_version):
    """
    Асинхронно извлекает текущую и до 4 предыдущих версий артефакта из maven-metadata.xml.

    Args:
        base_repository_url (str): Базовый URL репозитория.
        group_id (str): Группа артефакта.
        artifact_id (str): Идентификатор артефакта.
        start_version (str): Текущая версия для анализа.

    Returns:
        list: Список версий для анализа (включая текущую и до 4 предыдущих).
    """
    metadata_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(metadata_url, timeout=10) as response:
                if response.status != 200:
                    log_warning(f"[Version Retrieval] Failed to fetch metadata from {metadata_url}. HTTP Status: {response.status}")
                    return []

                metadata_content = await response.text()
                try:
                    metadata_xml = ET.fromstring(metadata_content)
                    all_versions = [version.text for version in metadata_xml.findall(".//version")]
                    log_info(f"[Version Retrieval] Found versions: {all_versions}")
                except ET.ParseError as e:
                    log_error(f"[Version Retrieval] Failed to parse XML from {metadata_url}: {e}")
                    return []

        # Проверяем наличие текущей версии
        if start_version not in all_versions:
            log_warning(f"[Version Check] Start version {start_version} not found.")
            return []

        # Выбираем текущую и до 4 предыдущих версий
        start_index = all_versions.index(start_version)
        selected_versions = all_versions[max(0, start_index - 4): start_index + 1]
        log_info(f"[Version Retrieval] Selected versions for analysis: {selected_versions}")
        return selected_versions

    except aiohttp.ClientError as e:
        log_error(f"[Version Retrieval] Client error while accessing {metadata_url}: {e}")
    except asyncio.TimeoutError:
        log_error(f"[Version Retrieval] Timeout while accessing {metadata_url}")
    except Exception as e:
        log_error(f"[Version Retrieval] Unexpected error: {e}")

    return []  # Возвращаем пустой список при ошибке


