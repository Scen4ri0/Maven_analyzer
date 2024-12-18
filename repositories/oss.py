import requests

def check_oss(group_id, artifact_id, version):
    """
    Проверяет наличие артефакта в OSS Sonatype и возвращает URL артефакта и базовый URL репозитория.
    Поддерживает проверку артефактов с разными расширениями.
    """
    base_repository_url = "https://oss.sonatype.org/content/repositories/releases"
    artifact_base_path = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}"

    # Список поддерживаемых расширений
    extensions = ["jar", "aar", "pom"]

    for ext in extensions:
        artifact_url = f"{artifact_base_path}.{ext}"
        response = requests.head(artifact_url)
        if response.status_code == 200:
            return artifact_url, base_repository_url

    return None, None
