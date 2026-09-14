(function () {
    "use strict";

    const page = document.querySelector(
        "[data-market-live]"
    );

    if (!page) {
        return;
    }

    const endpoint = page.dataset.liveEndpoint;

    const cards = new Map(
        Array.from(
            page.querySelectorAll("[data-coin-id]")
        ).map((card) => [
            card.dataset.coinId,
            card,
        ])
    );

    const badge = page.querySelector(
        ".market-badge"
    );

    let refreshTimer = null;
    let activeRequest = null;


    function formatPrice(value) {
        const number = Number(value);

        if (!Number.isFinite(number)) {
            return "—";
        }

        let decimals = 2;

        if (number < 0.01) {
            decimals = 8;
        } else if (number < 1) {
            decimals = 4;
        }

        return new Intl.NumberFormat(
            "en-US",
            {
                style: "currency",
                currency: "USD",
                minimumFractionDigits: 2,
                maximumFractionDigits: decimals,
            }
        ).format(number);
    }


    function formatMoney(value) {
        const number = Number(value);

        if (!Number.isFinite(number)) {
            return "—";
        }

        return new Intl.NumberFormat(
            "en-US",
            {
                style: "currency",
                currency: "USD",
                notation: "compact",
                maximumFractionDigits: 2,
            }
        ).format(number);
    }


    function updateChange(element, value) {
        if (!element) {
            return;
        }

        const change = Number(value);

        element.className = "market-change";

        if (!Number.isFinite(change)) {
            element.textContent = "24h unavailable";

            element.classList.add(
                "market-change--neutral"
            );

            return;
        }

        if (change > 0) {
            element.textContent =
                `▲ ${change.toFixed(2)}%`;

            element.classList.add(
                "market-change--positive"
            );

            return;
        }

        if (change < 0) {
            element.textContent =
                `▼ ${change.toFixed(2)}%`;

            element.classList.add(
                "market-change--negative"
            );

            return;
        }

        element.textContent = "0.00%";

        element.classList.add(
            "market-change--neutral"
        );
    }


    function updateCard(asset) {
        const card = cards.get(asset.coin_id);

        if (!card) {
            return;
        }

        card.dataset.price = String(
            asset.price_usd ?? 0
        );

        card.dataset.marketCap = String(
            asset.market_cap_usd ?? 0
        );

        card.dataset.change = String(
            asset.price_change_24h ?? 0
        );


        const price = card.querySelector(
            ".market-price"
        );

        if (price) {
            price.textContent = formatPrice(
                asset.price_usd
            );
        }


        updateChange(
            card.querySelector(".market-change"),
            asset.price_change_24h
        );


        const moneyValues = card.querySelectorAll(
            "[data-format-money]"
        );

        if (moneyValues[0]) {
            moneyValues[0].textContent =
                formatMoney(
                    asset.market_cap_usd
                );
        }

        if (moneyValues[1]) {
            moneyValues[1].textContent =
                formatMoney(
                    asset.volume_24h_usd
                );
        }


        const rank = card.querySelector(
            ".market-rank"
        );

        if (rank) {
            rank.textContent =
                asset.market_cap_rank
                    ? `#${asset.market_cap_rank}`
                    : "—";
        }


        const updated = card.querySelector(
            ".market-updated"
        );

        if (updated) {
            const updateDate = new Date(
                asset.last_updated
            );

            updated.textContent =
                Number.isNaN(updateDate.getTime())
                    ? "Updated just now"
                    : (
                        "Live update " +
                        updateDate.toLocaleTimeString()
                    );
        }
    }


    async function refreshMarket(options = {}) {
        const force = Boolean(options.force);

        if (document.hidden) {
            return;
        }

        if (activeRequest) {
            if (!force) {
                return;
            }

            activeRequest.abort();
        }

        const controller = new AbortController();

        activeRequest = controller;

        if (badge) {
            badge.textContent = "Updating market…";
        }

        try {
            const response = await fetch(
                endpoint,
                {
                    headers: {
                        Accept: "application/json",
                    },

                    cache: "no-store",
                    signal: controller.signal,
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    "Live market request failed."
                );
            }

            if (activeRequest !== controller) {
                return;
            }

            const assets = Array.isArray(data.assets)
                ? data.assets
                : [];

            assets.forEach(updateCard);

            document.dispatchEvent(
                new CustomEvent(
                    "happywallet:market-updated"
                )
            );

            if (badge) {
                badge.textContent =
                    "Live · " +
                    new Date().toLocaleTimeString();

                badge.removeAttribute("title");
            }
        } catch (error) {
            if (
                error instanceof DOMException &&
                error.name === "AbortError"
            ) {
                return;
            }

            if (badge) {
                badge.textContent =
                    "Live data unavailable";

                badge.title =
                    error instanceof Error
                        ? error.message
                        : "Market update failed.";
            }
        } finally {
            if (activeRequest === controller) {
                activeRequest = null;
            }
        }
    }


    function stopRefreshTimer() {
        if (refreshTimer !== null) {
            window.clearInterval(
                refreshTimer
            );

            refreshTimer = null;
        }
    }


    function startRefreshTimer() {
        stopRefreshTimer();

        refreshTimer = window.setInterval(
            refreshMarket,
            60000
        );
    }


    function stopActiveRequest() {
        if (activeRequest) {
            activeRequest.abort();
            activeRequest = null;
        }
    }


    if (!document.hidden) {
        refreshMarket();
        startRefreshTimer();
    }

    document.addEventListener(
        "visibilitychange",
        () => {
            if (document.hidden) {
                stopRefreshTimer();
                stopActiveRequest();
                return;
            }

            refreshMarket({
                force: true,
            });

            startRefreshTimer();
        }
    );

    window.addEventListener(
        "pagehide",
        () => {
            stopRefreshTimer();
            stopActiveRequest();
        }
    );
}());
