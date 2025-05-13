self.addEventListener('install', evt => evt.waitUntil(caches.open('v1').then(cache => cache.addAll(['/','/app.js','/styles.css'])));
self.addEventListener('fetch', evt => {
    evt.respondWith(caches.match(evt.request).then(res => res || fetch(evt.request)));
});
