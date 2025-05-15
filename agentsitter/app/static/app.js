if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
        .then(reg => console.log('SW registered', reg))
        .catch(console.error);
}
async function requestPermission() {
    const res = await Notification.requestPermission();
    if (res !== 'granted') {
        throw new Error('Notifications permission denied');
    }
}

function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

async function subscribeUser() {
    const sw = await navigator.serviceWorker.ready;
    const sub = await sw.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array('<VAPID_PUBLIC_KEY>')
    });
    // Send `sub.toJSON()` → your backend
    await fetch('/api/save-subscription', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(sub.toJSON())
    });
}

Notification.requestPermission()
    .then(perm => {
        if (perm === 'granted') {
            subscribeUser().catch(console.error);
        } else {
            console.warn('Notifications permission was', perm);
        }
    })
    .catch(console.error);