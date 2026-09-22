(() => {
    "use strict";

    const root = document.querySelector(
        "[data-kraken-live-prices]"
    );

    if (!root) {
        return;
    }

    const endpoint = root.dataset.endpoint;

    const body = root.querySelector(
        "[data-kraken-prices-body]"
    );

    const status = root.querySelector(
        "[data-kraken-prices-status]"
    );

    const refreshButton = root.querySelector(
        "[data-kraken-refresh]"
    );

    if (!endpoint || !body || !status) {
        return;
    }

    const refreshInterval = 30000;

    let activeRequest = null;
    let refreshTimer = null;
    let lastSuccessfulUpdate = null;
    let hasRenderedPrices = false;

    const currencyFormatter = new Intl.NumberFormat(
        "en-US",
        {
            style: "currency",
            currency: "USD",
            minimumFractionDigits: 2,
            maximumFractionDigits: 8,
        }
    );

    const numberFormatter = new Intl.NumberFormat(
        "en-US",
        {
            maximumFractionDigits: 8,
        }
    );

    function setStatus(message, tone = "muted") {
        status.textContent = message;

        status.classList.remove(
            "text-muted",
            "text-success",
            "text-warning",
            "text-danger"
        );

        const toneClasses = {
            muted: "text-muted",
            success: "text-success",
            warning: "text-warning",
            danger: "text-danger",
        };

        status.classList.add(
            toneClasses[tone] || toneClasses.muted
        );
    }

    function createCell(value, className = "") {
        const cell = document.createElement("td");

        cell.textContent = value;
        cell.className = className;

        return cell;
    }

    function requireFiniteNumber(value, fieldName) {
        const number = Number(value);

        if (!Number.isFinite(number)) {
            throw new Error(
                `Invalid numeric value for ${fieldName}.`
            );
        }

        return number;
    }

    function renderPrices(prices) {
        if (!Array.isArray(prices) || prices.length === 0) {
            throw new Error(
                "Kraken returned no live prices."
            );
        }

        const fragment = document.createDocumentFragment();

        for (const item of prices) {
            if (!item || typeof item.symbol !== "string") {
                throw new Error(
                    "Invalid Kraken price record."
                );
            }

            const price = requireFiniteNumber(
                item.price,
                "price"
            );

            const bid = requireFiniteNumber(
                item.bid,
                "bid"
            );

            const ask = requireFiniteNumber(
                item.ask,
                "ask"
            );

            const percentage = requireFiniteNumber(
                item.change_percentage_24h,
                "24-hour change"
            );

            const volume = requireFiniteNumber(
                item.volume_24h,
                "24-hour volume"
            );

            const row = document.createElement("tr");

            let changeClass = "text-muted";

            if (percentage > 0) {
                changeClass = "text-success";
            } else if (percentage < 0) {
                changeClass = "text-danger";
            }

            const sign = percentage > 0 ? "+" : "";

            row.append(
                createCell(
                    item.symbol,
                    "fw-semibold"
                ),
                createCell(
                    currencyFormatter.format(price),
                    "fw-semibold"
                ),
                createCell(
                    currencyFormatter.format(bid)
                ),
                createCell(
                    currencyFormatter.format(ask)
                ),
                createCell(
                    `${sign}${percentage.toFixed(2)}%`,
                    `${changeClass} fw-semibold`
                ),
                createCell(
                    numberFormatter.format(volume)
                )
            );

            fragment.append(row);
        }

        /*
         * Only replace the existing table after every returned
         * record has been validated successfully.
         */
        body.replaceChildren(fragment);
        hasRenderedPrices = true;
    }

    function getRetrievedAt(value) {
        const retrievedAt = new Date(value);

        if (Number.isNaN(retrievedAt.getTime())) {
            return new Date();
        }

        return retrievedAt;
    }

    async function loadPrices({ force = false } = {}) {
        if (document.hidden && !force) {
            return;
        }

        if (activeRequest) {
            activeRequest.abort();
        }

        const requestController = new AbortController();
        activeRequest = requestController;

        if (refreshButton) {
            refreshButton.disabled = true;
        }

        if (hasRenderedPrices) {
            setStatus(
                "Refreshing Kraken public market data…"
            );
        } else {
            setStatus(
                "Loading Kraken public market data…"
            );
        }

        try {
            const response = await fetch(
                endpoint,
                {
                    method: "GET",
                    credentials: "same-origin",
                    cache: "no-store",
                    headers: {
                        Accept: "application/json",
                    },
                    signal: requestController.signal,
                }
            );

            if (!response.ok) {
                throw new Error(
                    `Price request failed: ${response.status}`
                );
            }

            const payload = await response.json();

            if (!Array.isArray(payload.prices)) {
                throw new Error(
                    "Invalid Kraken price response."
                );
            }

            renderPrices(payload.prices);

            lastSuccessfulUpdate = getRetrievedAt(
                payload.retrieved_at
            );

            setStatus(
                `Live Kraken public market data · Updated ${
                    lastSuccessfulUpdate.toLocaleTimeString()
                }`,
                "success"
            );
        } catch (error) {
            if (error.name === "AbortError") {
                return;
            }

            if (hasRenderedPrices) {
                const lastUpdateText = lastSuccessfulUpdate
                    ? ` · Last updated ${
                        lastSuccessfulUpdate.toLocaleTimeString()
                    }`
                    : "";

                setStatus(
                    `Update failed · Showing last known prices${
                        lastUpdateText
                    }`,
                    "warning"
                );
            } else {
                setStatus(
                    "Kraken prices are temporarily unavailable.",
                    "danger"
                );
            }

            console.warn(
                "Kraken live-price refresh failed.",
                error
            );
        } finally {
            /*
             * An older aborted request must not clear the state
             * belonging to a newer request.
             */
            if (activeRequest === requestController) {
                activeRequest = null;

                if (refreshButton) {
                    refreshButton.disabled = false;
                }
            }
        }
    }

    function scheduleRefresh() {
        if (refreshTimer) {
            window.clearInterval(refreshTimer);
        }

        refreshTimer = window.setInterval(
            () => loadPrices(),
            refreshInterval
        );
    }

    if (refreshButton) {
        refreshButton.addEventListener(
            "click",
            () => loadPrices({ force: true })
        );
    }

    document.addEventListener(
        "visibilitychange",
        () => {
            if (document.hidden) {
                if (activeRequest) {
                    activeRequest.abort();
                }

                return;
            }

            loadPrices({ force: true });
        }
    );

    window.addEventListener(
        "beforeunload",
        () => {
            if (activeRequest) {
                activeRequest.abort();
            }

            if (refreshTimer) {
                window.clearInterval(refreshTimer);
            }
        }
    );

    loadPrices({ force: true });
    scheduleRefresh();
})();