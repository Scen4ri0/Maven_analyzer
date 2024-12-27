# Maven Artifact Verifier

## Описание
**Maven Artifact Verifier** – это инструмент для проверки Maven артефактов на наличие проблем с версиями, подписями, контрибьюторами GitHub, а также для выполнения статического анализа и проверки песочницей VirusTotal (опционально).

### Возможности:
1. **Проверка репозиториев**:
   - Наличие артефактов в различных репозиториях (Sonatype Central, JitPack, JBoss и др.).
   - Сравнение версий между репозиториями.
2. **Подписи и контрибьюторы**:
   - Проверка валидности GPG-подписей артефактов.
   - Анализ контрибьюторов на GitHub для текущей и до 4 предыдущих версий.
3. **Проверка доменов и дат публикации**:
   - Проверка состояния домена и даты публикации артефактов (опционально, флаг `-d`).
4. **Статический анализ**:
   - Использование правил YARA для обнаружения подозрительных и вредоносных паттернов в Java-артефактах.
5. **Песочница VirusTotal**:
   - Отправка артефактов для анализа антивирусными движками (опционально, флаг `-s` и API-ключ).

---

## Формат входного файла

Входной файл представляет собой текстовый файл, содержащий список артефактов в формате:
```txt
group_id:artifact_id:version
```

**Пример:**
```txt
com.orhanobut:logger:2.2.0  
com.applovin:applovin-sdk:12.6.0
```

---

## Формат выходного файла

Выходной файл — это JSON с результатами анализа каждого артефакта.

**Пример:**
```json
{
    "artifact": "com.orhanobut:logger:2.2.0",
    "domain": "vulnerable",
    "recently_updated": false,
    "published_recently": false,
    "repositories_found": 2,
    "signature": "ok",
    "contributors_diff": true,
    "version_differences": true,
    "yara_analysis": {
        "artifact_path": "/path/to/artifact/logger-2.2.0.aar",
        "matches": [
            "MaliciousEncryptionUsage",
            "ComprehensiveJavaAnalysis"
        ]
    },
    "sandbox_analysis": {
        "total_engines": 76,
        "non_null_results": 0,
        "malicious_results": []
    },
    "risk": "high"
}
```

### Описание полей:
- **artifact**: Идентификатор артефакта (формат: `group_id:artifact_id:version`).
- **domain**: Статус домена (`ok`, `vulnerable`) — включается при флаге `-d`.
- **recently_updated**: Указывает, обновлялся ли домен с начала 2024 года (при флаге `-d`).
- **published_recently**: Указывает, опубликован ли артефакт после начала 2024 года (при флаге `-d`).
- **repositories_found**: Количество репозиториев, в которых был найден артефакт.
- **version_differences**: Указывает, есть ли различия в версиях между репозиториями.
- **signature**: Статус подписи артефакта (`ok`, `not_signed`, `potentially_exploited` и др.).
- **contributors_diff**: Указывает, есть ли различия среди контрибьюторов между версиями.
- **yara_analysis**: Результаты статического анализа:
  - `artifact_path`: Путь к проверенному артефакту.
  - `matches`: Список правил YARA, с которыми совпал артефакт.
- **sandbox_analysis**: Результаты песочницы (включается при флаге `-s`):
  - `total_engines`: Общее количество движков.
  - `non_null_results`: Количество движков с ненулевыми результатами.
  - `malicious_results`: Список движков, указавших на вредоносность.
- **risk**: Оценка риска для артефакта (`low`, `medium`, `high`).

---

## Аргументы командной строки
```bash
❯ python3 main.py --help
usage: main.py [-h] [-v] [-o OUTPUT] [-d] [-s] [--sandbox-api-key SANDBOX_API_KEY] [--github-token GITHUB_TOKEN] input

Verify Maven artifacts.

positional arguments:
  input                 Path to the file containing artifacts to verify or a single artifact in format 'groupId:artifactId:versionId'.

options:
  -h, --help            Show this help message and exit.
  -v, --verbose         Enable detailed output.
  -o OUTPUT, --output OUTPUT
                        Path to output file (optional).
  -d, --domain          Enable domain and publication date checks.
  -s, --sandbox         Enable sandbox scanning (e.g., VirusTotal).
  --sandbox-api-key SANDBOX_API_KEY
                        API key for the sandbox service (e.g., VirusTotal).
  --github-token GITHUB_TOKEN
                        GitHub API token for authenticated requests.
```

---

## Пример запуска

### 1. Базовая проверка:
```bash
python3 main.py libs.txt -o out.json --github-token YOUR_GITHUB_TOKEN
```

### 2. Включение проверки доменов и дат публикации:
```bash
python3 main.py libs.txt -o out.json -d --github-token YOUR_GITHUB_TOKEN
```

### 3. Включение песочницы VirusTotal:
```bash
python3 main.py libs.txt -o out.json -s --sandbox-api-key YOUR_SANDBOX_API_KEY --github-token YOUR_GITHUB_TOKEN
```

---

## Требования

- Python 3.8+
- Зависимости из `requirements.txt`. Установка:
```bash
  pip install -r requirements.txt
```

---

## Новые функции

### Статический анализ (YARA)
Инструмент использует правила YARA для анализа содержимого Java-артефактов. Определяются:
- Вредоносные конструкции (например, шифрование, обфускация).
- Подозрительные операции с файлами.
- Необычные ресурсы в артефакте.

### Песочница VirusTotal
При включении флага `-s` артефакты отправляются в VirusTotal для анализа:
- Проверяются антивирусными движками.
- Результаты включают количество движков с ненулевыми результатами и список обнаруженных угроз.
