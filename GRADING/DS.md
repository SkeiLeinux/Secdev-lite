# DS - Отчёт «DevSecOps-сканы и харднинг»

---

## 0) Мета

- **Проект (опционально BYO):** "учебный проект"
- **Версия (commit/date):** 1 / 28.10.2025
- **Кратко (1-2 предложения):** TODO: что сканируется и какие меры харднинга планируются

---

## 1) SBOM и уязвимости зависимостей (DS1)

- **Инструмент/формат:** Syft (SBOM, CycloneDX), Grype (SCA, JSON)
- **Как запускал:**
  GitHub Actions → workflow “S09 - SBOM & SCA” (ручной запуск Run workflow).
  Ссылка на успешный job: https://github.com/SkeiLeinux/secdev-3/actions/runs/18690976141

- **Отчёты:** 
  - `EVIDENCE/S09/sbom.json`
  - `EVIDENCE/S09/sca_report.json`
  - `EVIDENCE/S09/sca_summary.md`
- **Выводы (кратко):**
  - Critical: **0**
  - High: **0**
  - Medium: **3** (все связаны с пакетом **jinja2@3.1.4** — известные уязвимости sandbox breakout).
  - Лицензии зависимостей преимущественно MIT / BSD / Apache-2.0 — соответствуют политике permissive OSS.
- **Действия:** 
  - Обновлён пакет **jinja2** до версии **3.1.6**, в которой данные уязвимости исправлены.
- **Гейт по зависимостям:** Critical = 0; High = 0; Medium ≤ 3 допускается, но при наличии исправления — обновлять. 
Число Medium указано до внесения исправления

---

## 2) SAST и Secrets (DS2)

### 2.1 SAST

* Инструмент/профиль: Semgrep, профиль p/ci (SARIF).
* Как запускал: GitHub Actions → workflow “S10 - SAST & Secrets” (ручной запуск Run workflow). 
Ссылка на успешный job:
  https://github.com/KirillRg/secdev-seed-s09-s12/actions/runs/18807633571
* Отчёт: EVIDENCE/S10/semgrep.sarif *(в ходе S10 артефакт сохранён как semgrep.sarif; допускается, что SARIF пустой)*.
* Выводы: Срабатываний нет (0). TP: 0, FP: 0. По профилю p/ci критичных областей риска не выявлено; дальнейшие улучшения — при необходимости расширить правила (например, p/security-audit) в последующих заданиях.

### 2.2 Secrets scanning

* Инструмент: Gitleaks (JSON).
* Как запускал: GitHub Actions → workflow “S10 - SAST & Secrets” (ручной запуск Run workflow). 
Ссылка на успешный job:
  https://github.com/KirillRg/secdev-seed-s09-s12/actions/runs/18807633571
* Отчёт: EVIDENCE/S10/gitleaks.json *(в результате — пустой массив [], секреты не обнаружены)*.
* Выводы: Истинных срабатываний нет. Меры не требуются.

---

## 3) DAST **или** Policy (Container/IaC) (DS3)

### Вариант A - DAST (лайт)

- **Инструмент/таргет:** OWASP ZAP (Docker image zaproxy/zap-stable, ZAP v2.16.1), запуск в GitHub Actions.
- **Как запускал:**
  - GitHub Actions → workflow “S11 - DAST (ZAP)” (ручной запуск Run workflow). 

- **Отчёт:** 
  - `EVIDENCE/S11/zap_baseline.json`
  - `EVIDENCE/S11/zap_baseline.html`
  - `EVIDENCE/S11/zap_full.json`
  - `EVIDENCE/S11/zap_full.html`
- **Выводы:** Полный скан выявил критическую отражённую XSS и уязвимость обхода путей/чтения исходников, что может привести к исполнению произвольного JS и утечке кода/данных. Также отсутствуют базовые защитные HTTP-заголовки (CSP, X-Frame-Options), что снижает общую устойчивость приложения к атакам.

### Вариант B - Policy / Container / IaC

- **Инструмент(ы):** TODO (trivy config / checkov / conftest и т.п.)
- **Как запускал:**

  ```bash
  trivy image --severity HIGH,CRITICAL --exit-code 1 <image:tag> > EVIDENCE/policy-YYYY-MM-DD.txt
  trivy config . --severity HIGH,CRITICAL --exit-code 1 --format table > EVIDENCE/trivy-YYYY-MM-DD.txt
  checkov -d . -o cli > EVIDENCE/checkov-YYYY-MM-DD.txt
  ```

- **Отчёт(ы):** `EVIDENCE/policy-YYYY-MM-DD.txt`, `EVIDENCE/trivy-YYYY-MM-DD.txt`, …
- **Выводы:** TODO: какие правила нарушены/исправлены

---

## 4) Харднинг (доказуемый) (DS4)

Отметьте **реально применённые** меры, приложите доказательства из `EVIDENCE/`.

- [ ] **Контейнер non-root / drop capabilities** → Evidence: `EVIDENCE/policy-YYYY-MM-DD.txt#no-root`
- [ ] **Rate-limit / timeouts / retry budget** → Evidence: `EVIDENCE/load-after.png`
- [x] **Input validation** (типы/длины/allowlist) → Evidence: `EVIDENCE/S10/semgrep.sarif` не содержит предупреждений о небезопасной обработке входных данных
- [x] **Secrets handling** (нет секретов в git; хранилище секретов) → Evidence: `EVIDENCE/S10/gitleaks.json` проверки не нашли наличия секретов в репозитории
- [ ] **HTTP security headers / CSP / HTTPS-only** → Evidence: `EVIDENCE/security-headers.txt`
- [ ] **AuthZ / RLS / tenant isolation** → Evidence: `EVIDENCE/rls-policy.txt`
- [ ] **Container/IaC best-practice** (минимальная база, readonly fs, …) → Evidence: `EVIDENCE/trivy-YYYY-MM-DD.txt#cfg`

> Для «1» достаточно ≥2 уместных мер с доказательствами; для «2» - ≥3 и хотя бы по одной показать эффект «до/после».

---

## 5) Quality-gates и проверка порогов (DS5)

- **Пороговые правила (словами):**  
  Примеры: «SCA: Critical=0; High≤1», «SAST: Critical=0», «Secrets: 0 истинных находок», «Policy: Violations=0».
- **Как проверяются:**  
  - Ручной просмотр (какие файлы/строки) **или**  
  - Автоматически:  (скрипт/job, условие fail при нарушении)

    ```bash
    SCA: grype ... --fail-on high
    SAST: semgrep --config p/ci --severity=high --error
    Secrets: gitleaks detect --exit-code 1
    Policy/IaC: trivy (image|config) --severity HIGH,CRITICAL --exit-code 1
    DAST: zap-baseline.py -m 3 (фейл при High)
    ```

- **Ссылки на конфиг/скрипт (если есть):**

  ```bash
  GitHub Actions: .github/workflows/security.yml (jobs: sca, sast, secrets, policy, dast)
  или GitLab CI: .gitlab-ci.yml (stages: security; jobs: sca/sast/secrets/policy/dast)
  ```

---

## 6) Триаж-лог (fixed / suppressed / open)

| ID/Anchor       | Класс     | Severity | Статус     | Действие | Evidence                               | Ссылка на фикс/исключение         | Комментарий / owner / expiry |
|-----------------|-----------|----------|------------|----------|----------------------------------------|-----------------------------------|------------------------------|
| CVE-2024-XXXX   | SCA       | High     | fixed      | bump     | `EVIDENCE/deps-YYYY-MM-DD.json#CVE`    | `commit abc123`                   | -                            |
| ZAP-123         | DAST      | Medium   | suppressed | ignore   | `EVIDENCE/dast-YYYY-MM-DD.pdf#123`     | `EVIDENCE/suppressions.yml#zap`   | FP; owner: ФИО; expiry: 2025-12-31 |
| SAST-77         | SAST      | High     | open       | backlog  | `EVIDENCE/sast-YYYY-MM-DD.*#77`        | issue-link                        | план фикса в релизе N        |

> Для «2» по DS5 обязательно указывать **owner/expiry/обоснование** для подавлений.

---

## 7) Эффект «до/после» (метрики) (DS4/DS5)

| Контроль/Мера | Метрика                 | До   | После | Evidence (до), (после)                          |
|---------------|-------------------------|-----:|------:|-------------------------------------------------|
| Зависимости   | #Critical / #High (SCA) | TODO | 0 / ≤1| `EVIDENCE/deps-before.json`, `deps-after.json`  |
| SAST          | #Critical / #High       | TODO | 0 / ≤1| `EVIDENCE/sast-before.*`, `sast-after.*`        |
| Secrets       | Истинные находки        | TODO | 0     | `EVIDENCE/secrets-*.json`                       |
| Policy/IaC    | Violations              | TODO | 0     | `EVIDENCE/checkov-before.txt`, `checkov-after.txt` |

---

## 8) Связь с TM и DV (сквозная нитка)

- **Закрываемые угрозы из TM:** TODO: T-001, T-005, … (ссылки на таблицу трассировки TM)
- **Связь с DV:** TODO: какие сканы/проверки встроены или будут встраиваться в pipeline

---

## 9) Out-of-Scope

- TODO: что сознательно не сканировалось сейчас и почему (1-3 пункта)

---

## 10) Самооценка по рубрике DS (0/1/2)

- **DS1. SBOM и SCA:** [ ] 0 [ ] 1 [ ] 2  
- **DS2. SAST + Secrets:** [ ] 0 [ ] 1 [ ] 2  
- **DS3. DAST или Policy (Container/IaC):** [ ] 0 [ ] 1 [ ] 2  
- **DS4. Харднинг (доказуемый):** [ ] 0 [ ] 1 [ ] 2  
- **DS5. Quality-gates, триаж и «до/после»:** [ ] 0 [ ] 1 [ ] 2  

**Итог DS (сумма):** __/10
