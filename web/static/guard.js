(function () {
    // Перехват fetch
    const originalFetch = window.fetch;
    window.fetch = async function (...args) {
        const response = await originalFetch(...args);
        if (response.status === 403) {
            console.log('[GoGuard] 403 Forbidden detected.');
        }
        return response;
    };

    // Перехват XMLHttpRequest (Axios использует его)
    const originalSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function (...args) {
        this.addEventListener('load', function () {
            if (this.status === 403) {
                console.log('[GoGuard] XHR 403 Forbidden detected.');
            }
        });
        return originalSend.apply(this, args);
    };
})();