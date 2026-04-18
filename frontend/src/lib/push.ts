// Web Push helpers. Only importable in a browser; the service worker
// registration intentionally short-circuits when HTTPS is not in use
// because the PushManager API rejects insecure origins.
import { api } from '../api/client';

export interface PushSupport {
  supported: boolean;
  httpsOk: boolean;
  permission?: NotificationPermission;
  reason?: string;
}

export function pushSupport(): PushSupport {
  if (typeof window === 'undefined') {
    return { supported: false, httpsOk: false, reason: 'no window' };
  }
  const httpsOk = window.isSecureContext;
  const supported = 'serviceWorker' in navigator && 'PushManager' in window;
  if (!supported) {
    return { supported: false, httpsOk, reason: 'ServiceWorker or PushManager unavailable' };
  }
  return {
    supported: true,
    httpsOk,
    permission: Notification.permission,
  };
}

export async function registerPushSW(): Promise<ServiceWorkerRegistration> {
  return navigator.serviceWorker.register('/push-sw.js', { scope: '/' });
}

// urlBase64ToUint8Array: convert the VAPID public key (base64url) into
// the ArrayBuffer the PushManager expects. Standard snippet from the
// Web Push spec examples.
function urlBase64ToUint8Array(base64: string): Uint8Array {
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const normal = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = window.atob(normal);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

export async function subscribeToPush(): Promise<{ endpoint: string }> {
  const support = pushSupport();
  if (!support.supported) throw new Error('Web Push not supported in this browser');
  if (!support.httpsOk) throw new Error('Web Push requires HTTPS (or localhost)');

  const reg = await registerPushSW();
  const { public_key } = await api.vapidPublicKey();
  const perm = await Notification.requestPermission();
  if (perm !== 'granted') throw new Error('Notification permission denied');

  const keyBuf = urlBase64ToUint8Array(public_key).buffer as ArrayBuffer;
  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: keyBuf,
  });
  const json = sub.toJSON();
  const p256dh = json.keys?.p256dh ?? '';
  const auth = json.keys?.auth ?? '';
  await api.subscribePush({
    endpoint: sub.endpoint,
    p256dh_key: p256dh,
    auth_key: auth,
    user_agent: navigator.userAgent,
  });
  return { endpoint: sub.endpoint };
}

export async function unsubscribeFromPush(endpoint: string): Promise<void> {
  if ('serviceWorker' in navigator) {
    const reg = await navigator.serviceWorker.getRegistration('/');
    const sub = await reg?.pushManager.getSubscription();
    if (sub && sub.endpoint === endpoint) {
      await sub.unsubscribe();
    }
  }
  await api.unsubscribePush(endpoint);
}
