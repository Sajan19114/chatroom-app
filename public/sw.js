self.addEventListener("push", e => {
  const data = e.data?.json() || {};
  e.waitUntil(self.registration.showNotification(data.title || "ChatRoom", {
    body: data.body || "New message",
    icon: "/icon.png",
    badge: "/icon.png",
    vibrate: [100, 50, 100],
    data: { url: data.url || "/" }
  }));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  e.waitUntil(clients.openWindow(e.notification.data?.url || "/"));
});
