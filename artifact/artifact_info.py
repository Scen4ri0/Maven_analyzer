# artifact/artifact_info.py

from artifact.artifact_status import ArtifactStatus
from utils.logging import log_info, log_error, log_warning

def get_artifact_info(group_id, artifact_id, version):
    """
    Возвращает ссылки на артефакты и подписи для заданного идентификатора.
    """
    base_url = "https://repo1.maven.org/maven2"
    artifact_path = f"{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}"
    return {
        "jar": f"{base_url}/{artifact_path}.jar",
        "jar_md5": f"{base_url}/{artifact_path}.jar.md5",
        "jar_sha1": f"{base_url}/{artifact_path}.jar.sha1",
        "signature": f"{base_url}/{artifact_path}.jar.asc",
        "pom": f"{base_url}/{artifact_path}.pom",
        "pom_md5": f"{base_url}/{artifact_path}.pom.md5",
        "pom_sha1": f"{base_url}/{artifact_path}.pom.sha1",
        "pom_signature": f"{base_url}/{artifact_path}.pom.asc"
    }


def record_artifact_status(artifact_id, status):
    """
    Записывает статус артефакта в соответствующий файл.
    """
    # Определяем имя файла для записи статуса
    if status == ArtifactStatus.VALID:
        filename = "all_ok.txt"
    elif status == ArtifactStatus.NOT_FOUND:
        filename = "not_found.txt"
    elif status == ArtifactStatus.POTENTIALLY_EXPLOITED:
        filename = "potentially_exploited.txt"
    elif status == ArtifactStatus.NOT_SIGNED:  # Новый статус
        filename = "not_signed.txt"
    else:
        log_error(f"Unknown status for artifact: {artifact_id}")
        return

    # Записываем в соответствующий файл
    try:
        with open(filename, "a") as f:
            f.write(f"{artifact_id}\n")
        log_info(f"Recorded status '{status}' for artifact: {artifact_id}")
    except Exception as e:
        log_error(f"Error writing status '{status}' for artifact '{artifact_id}': {e}")
