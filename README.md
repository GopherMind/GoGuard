# GoGuard 🛡️

Система защиты веб-приложений от ботов, DDoS атак и автоматизированных запросов без использования сторонних сервисов.

## 🎯 Возможности

### Server-Side защита:
- ✅ Rate limiting по IP (60 секунд)
- ✅ Fingerprinting по IP + User-Agent (5 минут)
- ✅ Проверка HTTP headers (User-Agent, Accept-Language, Accept-Encoding)
- ✅ Проверка Sec-Fetch-* headers (с учетом Safari)
- ✅ Проверка TLS версии
- ✅ Блокировка по risk score

### Client-Side защита (SDK):
- ✅ Детекция автоматизации (Puppeteer, Selenium, WebDriver)
- ✅ Поведенческий анализ (движение мыши, клики, нажатия клавиш)
- ✅ Canvas fingerprinting
- ✅ WebGL fingerprinting
- ✅ Системная информация (screen, timezone, languages)
- ✅ Автоматическое добавление headers ко всем запросам

### Визуальные страницы:
- 🛡️ Страница блокировки (blocked.html)
- 🔒 JavaScript challenge (challenge.html)
- 📄 Пример защищенной страницы (example.html)

## 📦 Структура проекта

```
GoGuard/
├── cmd/goguard/main.go          # Точка входа
├── internal/
│   ├── database/                # Redis операции
│   └── proxy/                   # Reverse proxy с защитой
├── pkg/
│   ├── utils/                   # Утилиты
│   │   ├── fingerprint.go       # Трекинг пользователей
│   │   ├── Headers.go           # Проверка headers
│   │   ├── client_fingerprint.go # Проверка SDK данных
│   │   └── ip.go                # Извлечение IP
│   └── pages/                   # HTML страницы
│       └── pages.go             # Отправка HTML
└── web/
    ├── static/
    │   └── goguard-sdk.js       # Client-side SDK
    └── templates/
        ├── blocked.html         # Страница блокировки
        ├── challenge.html       # JS challenge
        └── example.html         # Пример использования
```

## 🚀 Быстрый старт

### 1. Установка зависимостей

```bash
go mod download
```

### 2. Запуск Redis

```bash
# Windows (через WSL или Docker)
docker run -d -p 6379:6379 redis

# Linux/Mac
redis-server
```

### 3. Запуск GoGuard

```bash
go run cmd/goguard/main.go
```

Сервер запустится на `http://localhost:8080`

## 📝 Использование SDK на вашем сайте

### Вариант 1: Подключить SDK напрямую

```html
<!DOCTYPE html>
<html>
<head>
    <!-- Подключаем GoGuard SDK -->
    <script src="/goguard/sdk/goguard-sdk.js"></script>
</head>
<body>
    <h1>Защищенная страница</h1>
    
    <script>
        // SDK автоматически инициализируется
        // Все fetch/XHR запросы будут защищены
        
        fetch('/api/data')
            .then(r => r.json())
            .then(data => console.log(data));
    </script>
</body>
</html>
```

### Вариант 2: Проверить статус SDK

```javascript
// Подождать инициализации SDK
setTimeout(() => {
    if (window.goguard) {
        console.log('Fingerprint:', window.goguard.fingerprint);
        console.log('Behavior Score:', window.goguard.behaviorScore);
        // 100 = человек, 0 = бот
    }
}, 3000);
```

## 🔧 Настройка уровней риска

### Текущие пороги (в `proxy.go`):

```go
risk >= 100  → Блокировка на 24 часа
risk >= 60   → JavaScript challenge
risk >= 30   → Логирование (пропускаем)
risk < 30    → Нормальный запрос
```

### Максимальный риск: 210+

**Server-side (до 170):**
- Нет User-Agent: +30
- Нет Accept-Language: +15
- Простой Accept-Language: +10
- Нет Accept-Encoding: +15
- Нет Sec-Fetch-Site: +5
- Нет Sec-Fetch-Mode: +5
- Нет Sec-Fetch-Dest: +5
- Нет IP: +40
- Старый TLS (<1.2): +20
- Rate limit (>100 req/min): +35

**Client-side (до 90):**
- Нет SDK: +40
- SDK Score 0-20: +50
- SDK Score 21-50: +30
- SDK Score 51-70: +15

## 📊 Примеры risk scores

| Клиент | Server Risk | Client Risk | Total | Действие |
|--------|-------------|-------------|-------|----------|
| Chrome (человек) | 0 | 0 | 0 | ✅ Пропустить |
| Safari (человек) | 10 | 0 | 10 | ✅ Пропустить |
| curl без headers | 80 | 40 | 120 | 🚫 Блокировка |
| Puppeteer (базовый) | 0 | 50 | 50 | ⚠️ Challenge |
| Puppeteer (продвинутый) | 0 | 30 | 30 | 📝 Логирование |
| Флуд (>100 req/min) | 35+ | 0+ | 35+ | ⚠️ Challenge |

## 🧪 Тестирование

### Тест 1: Нормальный браузер
```bash
curl http://localhost:8080
# Должен пройти или получить challenge
```

### Тест 2: Бот без headers
```bash
curl -H "User-Agent:" http://localhost:8080
# Должен быть заблокирован
```

### Тест 3: Rate limiting
```bash
for i in {1..150}; do curl http://localhost:8080; done
# После 100 запросов должна быть блокировка
```

### Тест 4: Puppeteer
```javascript
const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto('http://localhost:8080');
    // SDK должен детектировать webdriver
})();
```

## 📈 Мониторинг

Логи показывают:
```
MEDIUM RISK: example.com -> GET / | IP: 1.2.3.4 | Risk: 35 (server: 30, client: 5) | Rate: 5 | User: 2
HIGH RISK CHALLENGE: example.com -> GET / | IP: 1.2.3.4 | Risk: 65 (server: 15, client: 50) | Rate: 10 | User: 3
CRITICAL RISK BLOCKED: example.com -> GET / | IP: 1.2.3.4 | Risk: 120 (server: 80, client: 40) | Rate: 150 | User: 50
```

## 🔐 Что детектирует SDK

### Автоматизация:
- `navigator.webdriver === true` (Selenium)
- `/HeadlessChrome/` в User-Agent
- `window.cdc_*` переменные (Puppeteer)
- Отсутствие `window.chrome`
- 0 plugins (headless)
- 0 languages

### Поведение:
- Нет движения мыши
- Нет кликов
- Слишком быстрые действия (<500ms)

### Fingerprinting:
- Canvas rendering (уникален для GPU/драйвера)
- WebGL vendor/renderer
- Screen resolution, timezone, languages

## 🛠️ Расширение функционала

### Добавить новую проверку в Headers.go:

```go
// Проверка Referer
referer := r.Header.Get("Referer")
if r.Method == "POST" && referer == "" {
    risk += 15
}
```

### Добавить новую детекцию в SDK:

```javascript
// В detectAutomation()
signals.phantom = !!window.callPhantom; // PhantomJS
signals.nightmare = !!window.__nightmare; // Nightmare.js
```

## 📚 Дополнительно

### Альтернативы для production:
- Cloudflare Bot Management ($20/мес)
- FingerprintJS ($99/мес)
- DataDome (enterprise)

### Когда использовать GoGuard:
- ✅ Pet проекты
- ✅ Внутренние сервисы
- ✅ Обучение
- ✅ Базовая защита

### Когда НЕ использовать:
- ❌ Высоконагруженные production системы
- ❌ Финансовые сервисы
- ❌ Критичная инфраструктура

## 📄 Лицензия

MIT License - используйте свободно!
#   G o G u a r d  
 