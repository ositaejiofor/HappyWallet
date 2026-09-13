/*
 * HappyWallet Progressive Web App Service Worker
 *
 * Security model:
 * - Do NOT cache authenticated application pages.
 * - Do NOT cache API responses.
 * - Do NOT cache wallet/private-key/seed/transaction data.
 * - Cache only explicitly approved public/static resources.
 */

const CACHE_NAME = "happywallet-static-v2";

const STATIC_ASSETS = [
    "/offline/",
];


/*
 * Installation
 *
 * Cache only the public offline page.
 */
self.addEventListener("install", (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(STATIC_ASSETS))
            .then(() => self.skipWaiting())
    );
});


/*
 * Activation
 *
 * Remove old HappyWallet PWA caches.
 */
self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches.keys()
            .then((cacheNames) =>
                Promise.all(
                    cacheNames
                        .filter((cacheName) =>
                            cacheName.startsWith("happywallet-") &&
                            cacheName !== CACHE_NAME
                        )
                        .map((cacheName) => caches.delete(cacheName))
                )
            )
            .then(() => self.clients.claim())
    );
});


/*
 * Fetch handling
 *
 * IMPORTANT:
 * We deliberately do not cache normal application pages,
 * authenticated responses, API responses, wallet data, or
 * blockchain data.
 */
self.addEventListener("fetch", (event) => {
    const request = event.request;

    if (request.method !== "GET") {
        return;
    }

    const url = new URL(request.url);

    /*
     * Only handle requests belonging to HappyWallet itself.
     */
    if (url.origin !== self.location.origin) {
        return;
    }

    /*
     * Static assets:
     * network first, then previously cached asset if available.
     *
     * This section is intentionally limited to /static/.
     */
    if (url.pathname.startsWith("/static/")) {
        event.respondWith(
            fetch(request)
                .then((response) => {
                    if (response.ok) {
                        const responseClone = response.clone();

                        caches.open(CACHE_NAME)
                            .then((cache) => {
                                cache.put(request, responseClone);
                            });
                    }

                    return response;
                })
                .catch(() => caches.match(request))
        );

        return;
    }

    /*
     * Navigation requests:
     *
     * Never cache authenticated pages.
     *
     * If the network is unavailable, show the public offline page.
     */
    if (request.mode === "navigate") {
        event.respondWith(
            fetch(request)
                .catch(() => caches.match("/offline/"))
        );

        return;
    }

    /*
     * Everything else:
     *
     * Pass directly through to the network.
     */
});
