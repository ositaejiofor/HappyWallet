"use strict";

/*
 * HappyWallet production service worker.
 *
 * Security policy:
 * - Cache only the public offline shell and static presentation assets.
 * - Never cache authenticated pages.
 * - Never cache API, wallet, account, transaction or trading responses.
 * - Never cache private keys, recovery phrases or blockchain data.
 */

const CACHE_VERSION = "v5";
const OFFLINE_CACHE =
    `happywallet-offline-${CACHE_VERSION}`;

const OFFLINE_URL = "/offline/";

const OFFLINE_ASSETS = [
    OFFLINE_URL,
    "/static/css/offline.css",
    "/static/images/logo/logo.png",
];


/* Installation */

self.addEventListener(
    "install",
    function (event) {
        event.waitUntil(
            caches
                .open(OFFLINE_CACHE)
                .then(function (cache) {
                    return cache.addAll(
                        OFFLINE_ASSETS
                    );
                })
                .then(function () {
                    return self.skipWaiting();
                })
        );
    }
);


/* Activation */

self.addEventListener(
    "activate",
    function (event) {
        event.waitUntil(
            caches
                .keys()
                .then(function (cacheNames) {
                    return Promise.all(
                        cacheNames.map(
                            function (cacheName) {
                                const isHappyWalletCache =
                                    cacheName.startsWith(
                                        "happywallet-"
                                    );

                                if (
                                    isHappyWalletCache &&
                                    cacheName !== OFFLINE_CACHE
                                ) {
                                    return caches.delete(
                                        cacheName
                                    );
                                }

                                return Promise.resolve(
                                    false
                                );
                            }
                        )
                    );
                })
                .then(function () {
                    return self.clients.claim();
                })
        );
    }
);


/* Requests */

self.addEventListener(
    "fetch",
    function (event) {
        const request = event.request;

        if (request.method !== "GET") {
            return;
        }

        const url = new URL(request.url);

        if (url.origin !== self.location.origin) {
            return;
        }

        /*
         * Navigation requests always use the network.
         * The offline page is returned only when the network fails.
         * Normal application pages are never written to Cache Storage.
         */
        if (request.mode === "navigate") {
            event.respondWith(
                fetch(request).catch(
                    function () {
                        return caches.match(
                            OFFLINE_URL
                        );
                    }
                )
            );

            return;
        }

        /*
         * Only explicitly approved offline assets may be read
         * from the offline cache.
         */
        if (OFFLINE_ASSETS.includes(url.pathname)) {
            event.respondWith(
                caches
                    .match(request)
                    .then(function (cachedResponse) {
                        if (cachedResponse) {
                            return cachedResponse;
                        }

                        return fetch(request);
                    })
            );
        }
    }
);