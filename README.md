# Maven Artifact Verifier

## Описание
**Maven Artifact Verifier** – это инструмент для проверки Maven артефактов на наличие проблем с версиями, подписями и контрибьюторами GitHub. Также может проверять состояние домена и даты публикации, если активирована соответствующая опция.

Инструмент поддерживает:
1. Проверку наличия артефактов в различных репозиториях (Sonatype Central, JitPack, JBoss и др.).
2. Сравнение версий между репозиториями.
3. Проверку валидности GPG-подписей артефактов.
4. Анализ контрибьюторов на GitHub для текущей и до 4 предыдущих версий.
5. Проверку состояния домена и даты публикации (опционально).

---

## Формат входного файла

Входной файл представляет собой текстовый файл, содержащий список артефактов в следующем формате:

group_id:artifact_id:version

Каждая строка файла содержит артефакт, который будет проверяться.

**Пример входного файла:**
```txt
com.orhanobut:logger:2.2.0  
com.applovin:applovin-sdk:12.6.0
```  

---

##  Аргументы командной строки

```bash
❯ python3 main.py --help
usage: main.py [-h] [-v] -o OUTPUT [-d] [--github-token GITHUB_TOKEN] input_file

Verify Maven artifacts from a file.

positional arguments:
  input_file            Path to the file containing artifacts to verify.

options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable detailed output.
  -o OUTPUT, --output OUTPUT
                        Path to output file.
  -d, --domain          Enable domain and publication date checks.
  --github-token GITHUB_TOKEN
                        GitHub API token for authenticated requests.
```

---

## Формат выходного файла

Выходной файл представляет собой JSON-объект с результатами анализа каждого артефакта.

Пример результата:

```json
{
    "artifact": "com.orhanobut:logger:2.2.0",
    "repositories_found": 2,
    "version_differences": true,
    "signature": "ok",
    "contributors_diff": true,
    "domain": "ok",
    "recently_updated": false,
    "published_recently": true,
    "risk": "medium"
}
```

### Описание полей:
- **artifact**: Идентификатор артефакта (group_id:artifact_id:version).
- **repositories_found**: Количество репозиториев, в которых был найден артефакт.
- **version_differences**: true, если есть различия между версиями артефакта в репозиториях.
- **signature**: Статус подписи артефакта (ok, not_signed, potentially_exploited и т.д.).
- **contributors_diff**: true, если есть различия среди контрибьюторов.
- **domain**: Статус домена (ok или vulnerable) — включается при передаче флага -d.
- **recently_updated**: true, если домен был обновлен с начала 2024 года — включается при передаче флага -d.
- **published_recently**: true, если артефакт был опубликован после начала 2024 года — включается при передаче флага -d.
- **risk**: Общая оценка риска для артефакта (low, medium, high).

---

## Пример запуска

Пример запуска скрипта для проверки артефактов из файла `libs.txt` с включенной опцией проверки домена и использованием GitHub API токена:

python3 main.py -o out.json libs.txt -v -d --github-token YOUR_GITHUB_TOKEN  

Где:  
- `libs.txt` – файл со списком артефактов.  
- `-o out.json` – путь для сохранения результатов проверки.  
- `-v` – режим подробного вывода.  
- `-d` – активация проверки домена и даты публикации.  
- `--github-token` – токен для доступа к GitHub.  
