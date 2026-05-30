/**
 * GoGuard SDK - Client-side bot detection
 * Собирает поведенческие данные и отправляет fingerprint на backend
 */
console.log('[GoGuard] SDK script executing, origin:', window.location.origin);

function getGoguardScript() {
    console.log('[GoGuard] Attempting to find script tag...');
    if (document.currentScript) {
        console.log('[GoGuard] Found via document.currentScript:', document.currentScript.src);
        return document.currentScript;
    }
    const scripts = document.getElementsByTagName('script');
    console.log('[GoGuard] Searching through', scripts.length, 'scripts...');
    for (let i = 0; i < scripts.length; i++) {
        const s = scripts[i];
        console.log(`[GoGuard] Checking script ${i}:`, s.src);
        if (s.src && s.src.includes('goguard-sdk.js')) {
            console.log('[GoGuard] Found match via search:', s.src);
            return s;
        }
    }
    console.warn('[GoGuard] Could not find own script tag!');
    return null;
}

const goguardScript = getGoguardScript();

class GoGuardSDK {
    constructor() {
        console.log('[GoGuard] constructor started');
        this.fingerprint = null;
        this.behaviorScore = 100;
        this.mouseData = [];
        this.clicks = [];
        this.keystrokes = [];
        this.sessionEvents = [];      // буфер событий между отправками
        this.startTime = Date.now();
        this.collectInterval = null;
        
        this.siteKey = goguardScript?.getAttribute('data-site-key') || '';
        this.sessionId = this.getOrCreateSessionId();

        // Check if we are running through the proxy on the same domain and port
        const currentHost = window.location.host;
        this.isProxyMode = currentHost === this.siteKey || !this.siteKey;

        // Determine proxy origin
        if (goguardScript?.src) {
            try {
                const scriptUrl = new URL(goguardScript.src);
                // If script is loaded from a different host/port, use absolute URL
                if (scriptUrl.host !== currentHost) {
                    this.proxyOrigin = scriptUrl.origin;
                    this.isProxyMode = false; // Override if explicitly cross-origin
                } else {
                    this.proxyOrigin = ''; // Same origin, use relative paths
                }
            } catch (e) {
                this.proxyOrigin = ''; 
            }
        } else {
            this.proxyOrigin = '';
        }

        console.log('[GoGuard] SDK fully initialized:', {
            siteKey: this.siteKey,
            proxyOrigin: this.proxyOrigin,
            isProxyMode: this.isProxyMode,
            currentHost: currentHost
        });
        this.init();
    }
    //Http
    getOrCreateSessionId() {
        // Временный ID до получения от сервера
        return crypto.randomUUID?.() || Math.random().toString(36).slice(2);
    }

    async init() {
        this.startTracking();
        this.interceptRequests();
        // Первичный fingerprint — без ожидания
        const initialData = await this.collectSnapshot();
        this.fingerprint = await this.generateFingerprint(initialData);

        // Первая отправка через 3 секунды
        setTimeout(() => this.sendSnapshot(), 3000);

        // Периодическая отправка каждые 5-6 секунд (случайный интервал против детектирования)
        this.collectInterval = setInterval(() => {
            this.sendSnapshot();
        }, this.randomInterval(5000, 6500));

        // Отправка при уходе со страницы
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'hidden') {
                this.sendSnapshot(true); // beacon mode
            }
        });
    }

    randomInterval(min, max) {
        return Math.floor(Math.random() * (max - min)) + min;
    }

    startTracking() {
        // Буферизируем события между отправками
        document.addEventListener('mousemove', (e) => {
            this.sessionEvents.push({
                type: 'move',
                x: e.clientX,
                y: e.clientY,
                t: Date.now() - this.startTime
            });
        });

        document.addEventListener('click', (e) => {
            this.sessionEvents.push({
                type: 'click',
                x: e.clientX,
                y: e.clientY,
                t: Date.now() - this.startTime
            });
            this.clicks.push({ x: e.clientX, y: e.clientY, t: Date.now() });
        });

        document.addEventListener('keydown', (e) => {
            // Не сохраняем сами клавиши — только факт нажатия
            this.keystrokes.push(Date.now() - this.startTime);
            this.sessionEvents.push({
                type: 'key',
                t: Date.now() - this.startTime
            });
        });

        // Scroll
        document.addEventListener('scroll', () => {
            this.sessionEvents.push({
                type: 'scroll',
                y: window.scrollY,
                t: Date.now() - this.startTime
            });
        });
    }

    // Анализ качества движений мыши
    analyzeMouseQuality(events) {
        const moves = events.filter(e => e.type === 'move');
        if (moves.length < 3) return { quality: 0, suspicious: true };

        const speeds = [];
        const angles = [];

        for (let i = 1; i < moves.length; i++) {
            const prev = moves[i - 1];
            const curr = moves[i];
            const dt = (curr.t - prev.t) / 1000;
            if (dt <= 0) continue;

            const dist = Math.hypot(curr.x - prev.x, curr.y - prev.y);
            speeds.push(dist / dt);
            angles.push(Math.atan2(curr.y - prev.y, curr.x - prev.x));
        }

        // Ботовые движения: постоянная скорость (низкая дисперсия)
        const speedVariance = this.variance(speeds);
        // Ботовые движения: прямые линии (низкая дисперсия углов)
        const angleVariance = this.variance(angles);

        return {
            count: moves.length,
            avgSpeed: this.avg(speeds),
            speedVariance,
            angleVariance,
            // Низкая дисперсия = подозрительно
            suspicious: speedVariance < 50 && moves.length > 10
        };
    }

    variance(arr) {
        if (arr.length < 2) return 0;
        const mean = this.avg(arr);
        return this.avg(arr.map(v => (v - mean) ** 2));
    }

    avg(arr) {
        if (!arr.length) return 0;
        return arr.reduce((a, b) => a + b, 0) / arr.length;
    }

    async collectSnapshot() {
        // Берём и очищаем буфер событий
        const events = [...this.sessionEvents];
        this.sessionEvents = [];

        const mouseAnalysis = this.analyzeMouseQuality(events);

        return {
            siteKey: this.siteKey,
            sessionId: this.sessionId,
            timestamp: Date.now(),
            timeOnPage: Date.now() - this.startTime,

            automation: this.detectAutomation(),
            canvas: this.getCanvasFingerprint(),
            webgl: this.getWebGLFingerprint(),

            // Только дельта событий с момента последней отправки
            events: {
                total: events.length,
                moves: events.filter(e => e.type === 'move').length,
                clicks: events.filter(e => e.type === 'click').length,
                keys: events.filter(e => e.type === 'key').length,
                scrolls: events.filter(e => e.type === 'scroll').length,
            },
            mouseAnalysis,

            system: {
                screen: {
                    width: screen.width,
                    height: screen.height,
                    colorDepth: screen.colorDepth,
                    pixelRatio: window.devicePixelRatio
                },
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timezoneOffset: new Date().getTimezoneOffset(),
                languages: navigator.languages,
                hardwareConcurrency: navigator.hardwareConcurrency,
                deviceMemory: navigator.deviceMemory,
                platform: navigator.platform,
                // Дополнительно
                cookieEnabled: navigator.cookieEnabled,
                doNotTrack: navigator.doNotTrack,
                connectionType: navigator.connection?.effectiveType,
            }
        };
    }

    async sendSnapshot(useBeacon = false) {
        const data = await this.collectSnapshot();
        const fp = await this.generateFingerprint(data);
        this.fingerprint = fp;

        const payload = JSON.stringify(data);
        const endpoint = goguardScript?.getAttribute('data-collect-url') || 
                        (this.isProxyMode ? '/goguard/collect' : `${this.proxyOrigin}/goguard/collect`);
        
        console.log('[GoGuard] sending snapshot to:', endpoint);

        if (useBeacon && navigator.sendBeacon) {
            // sendBeacon работает даже при закрытии страницы
            navigator.sendBeacon(endpoint, new Blob([payload], { type: 'application/json' }));
            return;
        }

        try {
            const resp = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    // Score не передаём — сервер считает сам
                    'X-GoGuard-FP': fp,
                    'X-GoGuard-SiteKey': this.siteKey,
                },
                body: payload,
                // Не блокируем основные запросы
                priority: 'low',
                keepalive: true,
            });

            if (resp.ok) {
                const result = await resp.json();
                // Сервер может вернуть новый score или команду
                if (result.action === 'challenge') {
                    this.triggerChallenge();
                }
                if (result.sessionId) {
                    this.sessionId = result.sessionId; // обновляем ID от сервера
                }
            }
        } catch (e) {
            // Сбой сети — не критично, продолжаем
        }
    }
    //endpoint
    // Вызывается при подозрении со стороны сервера
    triggerChallenge() {
        clearInterval(this.collectInterval);

        // Always stay on the current origin — the proxy serves /goguard/challenge
        // transparently, so no cross-origin URL is ever needed.
        const returnUrl = encodeURIComponent(window.location.href);
        window.location.href = `/goguard/challenge?return=${returnUrl}`;
    }

    interceptRequests() {
        const originalFetch = window.fetch;
        const self = this;

        window.fetch = async function (url, options = {}) {
            // Не перехватываем наши собственные отправки
            if (typeof url === 'string' && url.includes('/goguard/')) {
                return originalFetch(url, options);
            }

            options.headers = options.headers || {};
            if (self.fingerprint) {
                options.headers['X-GoGuard-FP'] = self.fingerprint;
            }
            options.headers['X-GoGuard-SiteKey'] = self.siteKey;

            try {
                const response = await originalFetch(url, options);

                // Challenge can come back as 401 (verification required) or
                // 403 (legacy). The X-GoGuard-Challenge header is the source
                // of truth — the status code only mirrors it.
                if (response.status === 401 || response.status === 403) {
                    const isChallenge = response.headers.get('X-GoGuard-Challenge') === 'true';
                    if (isChallenge) {
                        console.log('[GoGuard] AJAX Challenge detected. Redirecting...');
                        self.triggerChallenge();
                    }
                }
                return response;
            } catch (err) {
                throw err;
            }
        };

        // XHR
        const OrigSend = XMLHttpRequest.prototype.send;
        const OrigOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (method, url, ...rest) {
            this._goguard_url = url;
            return OrigOpen.call(this, method, url, ...rest);
        };
        XMLHttpRequest.prototype.send = function (...args) {
            if (this._goguard_url?.includes('/goguard/')) {
                return OrigSend.apply(this, args);
            }

            this.setRequestHeader('X-GoGuard-SiteKey', self.siteKey);
            if (self.fingerprint) {
                this.setRequestHeader('X-GoGuard-FP', self.fingerprint);
            }

            const xhr = this;
            this.addEventListener('load', function () {
                if (xhr.status === 401 || xhr.status === 403) {
                    const isChallenge = xhr.getResponseHeader('X-GoGuard-Challenge') === 'true';
                    if (isChallenge) {
                        console.log('[GoGuard] XHR Challenge detected. Redirecting...');
                        self.triggerChallenge();
                    }
                }
            });

            return OrigSend.apply(this, args);
        };
    }

    detectAutomation() {
        const signals = {};
        signals.webdriver = navigator.webdriver === true;
        signals.headless = /HeadlessChrome/.test(navigator.userAgent);
        signals.cdp = !!(
            window.cdc_adoQpoasnfa76pfcZLmcfl_Array ||
            window.cdc_adoQpoasnfa76pfcZLmcfl_Promise ||
            window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol
        );
        // Убрали noChrome — слишком много ложных срабатываний
        signals.noPlugins = navigator.plugins.length === 0;
        signals.noLanguages = navigator.languages.length === 0;
        // Новые сигналы
        signals.phantomjs = !!window.callPhantom || !!window._phantom;
        signals.nightmare = !!window.__nightmare;
        signals.selenium = !!(document.$cdc_asdjflasutopfhvcZLmcfl_ || window.document.__selenium_unwrapped);
        return signals;
    }

    getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('GoGuard 🛡️', 2, 15);
            return canvas.toDataURL();
        } catch (e) {
            return null;
        }
    }

    getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return null;
            const dbg = gl.getExtension('WEBGL_debug_renderer_info');
            return {
                vendor: gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL),
                renderer: gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)
            };
        } catch (e) {
            return null;
        }
    }

    async generateFingerprint(data) {
        // Исключаем изменяемые поля из fingerprint
        const stable = {
            canvas: data.canvas,
            webgl: data.webgl,
            system: data.system,
            automation: data.automation,
            siteKey: data.siteKey,
        };
        const str = JSON.stringify(stable);
        const buffer = new TextEncoder().encode(str);
        const hash = await crypto.subtle.digest('SHA-256', buffer);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => { window.goguard = new GoGuardSDK(); });
} else {
    window.goguard = new GoGuardSDK();
}


