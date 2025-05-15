// No caching - only handle push notifications
self.addEventListener('install', evt => {
  self.skipWaiting();
});

self.addEventListener('activate', evt => {
  // Clear any existing caches
  evt.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => caches.delete(cacheName))
      );
    }).then(() => {
      return self.clients.claim();
    })
  );
});

// Bypass cache for all fetch requests
self.addEventListener('fetch', evt => {
  evt.respondWith(fetch(evt.request));
});

// Push notification handling
self.addEventListener('push', event => {
  const data = event.data.json();
  const { title, body, url } = data;
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      data: { url },
      icon: '/icons/192.png'
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.openWindow(event.notification.data.url)
  );
});