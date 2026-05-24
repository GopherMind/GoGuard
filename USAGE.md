# Краткая инструкция по использованию GoGuard

## Что мы создали:

### 1. **JavaScript SDK** (`web/static/goguard-sdk.js`)
- Автоматически собирает данные о поведении пользователя
- Детектирует автоматизацию (Puppeteer, Selenium)
- Добавляет защитные headers ко всем запросам

### 2. **HTML страницы**
- `blocked.html` - красивая страница блокировки
- `challenge.html` - JavaScript challenge с proof-of-work
- `example.html` - пример защищенной страницы

### 3. **Go обработчики**
- `pkg/pages/pages.go` - отправка HTML вместо JSON
- `pkg/utils/client_fingerprint.go` - проверка данных от SDK
- Обновленный `proxy.go` - интеграция всего вместе

## Как это работает:

```
1. Пользователь заходит на сайт
   ↓
2. Загружается goguard-sdk.js
   ↓
3. SDK собирает данные (2 секунды):
   - Движение мыши
   - Клики
   - Canvas/WebGL fingerprint
   - Детекция автоматизации
   ↓
4. SDK вычисляет Behavior Score (0-100)
   ↓
5. Все запросы получают headers:
   - X-GoGuard-FP: abc123...
   - X-GoGuard-Score: 95
   ↓
6. Backend проверяет:
   - Server-side risk (headers, TLS, rate)
   - Client-side risk (SDK score)
   ↓
7. Принимает решение:
   - risk < 30: пропустить
   - risk 30-59: логировать
   - risk 60-99: показать challenge
   - risk >= 100: заблокировать
```

## Быстрый тест:

### 1. Запустите проект:
```bash
# Терминал 1: Redis
docker run -d -p 6379:6379 redis

# Терминал 2: GoGuard
go run cmd/goguard/main.go
```

### 2. Откройте в браузере:
```
http://localhost:8080
```

### 3. Откройте консоль браузера (F12):
```javascript
// Через 3 секунды увидите:
console.log(window.goguard.fingerprint);
console.log(window.goguard.behaviorScore);
```

### 4. Тест с curl (должен заблокировать):
```bash
curl http://localhost:8080
# Risk будет высокий (нет headers + нет SDK)
```

### 5. Тест с Puppeteer:
```javascript
const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    
    await page.goto('http://localhost:8080');
    
    // SDK детектирует navigator.webdriver = true
    // Behavior Score будет низкий (20-50)
    // Backend покажет challenge или заблокирует
})();
```

## Что дальше:

### Для интеграции в ваш проект:

1. **Добавьте SDK на все страницы:**
```html
<script src="/goguard/sdk/goguard-sdk.js"></script>
```

2. **Настройте пороги риска** в `proxy.go`:
```go
if risk >= 100 {  // Измените на свои значения
    // Блокировка
}
```

3. **Кастомизируйте HTML страницы** в `web/templates/`

4. **Добавьте свои проверки** в `Headers.go` или `goguard-sdk.js`

## Примеры расширения:

### Добавить проверку Referer:
```go
// В pkg/utils/Headers.go
referer := r.Header.Get("Referer")
if r.Method == "POST" && referer == "" {
    risk += 15
}
```

### Добавить детекцию PhantomJS:
```javascript
// В web/static/goguard-sdk.js, в detectAutomation()
signals.phantom = !!window.callPhantom;
signals.nightmare = !!window.__nightmare;
```

### Изменить время сбора данных SDK:
```javascript
// В goguard-sdk.js, строка ~35
await this.sleep(2000); // Измените на 5000 для 5 секунд
```

## Готово! 🎉

Теперь у вас есть полноценная система защиты от ботов без сторонних сервисов!
