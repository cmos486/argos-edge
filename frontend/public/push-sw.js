// argos-edge Web Push service worker.
// Payload shape (matches the browser_push default template):
//   { title, body, severity, host }

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { title: 'argos alert', body: event.data ? event.data.text() : '' };
  }
  const title = data.title || 'argos alert';
  const body = data.body || '';
  const tag = data.host || data.severity || 'argos';
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag,
      icon: '/favicon.ico',
      data,
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const host = event.notification.data && event.notification.data.host;
  const target = host ? `/logs?host=${encodeURIComponent(host)}` : '/notifications';
  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((cls) => {
      for (const c of cls) {
        if ('focus' in c) {
          c.navigate(target);
          return c.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(target);
    }),
  );
});
