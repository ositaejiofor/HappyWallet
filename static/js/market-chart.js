(function () {
    "use strict";

    const root = document.querySelector("[data-market-chart]");

    if (!root) {
        return;
    }

    const canvas = root.querySelector("canvas");
    const status = root.querySelector("[data-chart-status]");
    const price = document.querySelector("[data-live-price]");
    const updated = document.querySelector("[data-live-updated]");
    const buttons = Array.from(
        root.querySelectorAll("[data-days]")
    );

    const endpoint = root.dataset.endpoint;
    const context = canvas && canvas.getContext("2d");

    if (!canvas || !context || !status || !endpoint) {
        return;
    }

    let selectedDays = 1;
    let candles = [];
    let resizeTimer = null;
    let refreshTimer = null;

    const usd = new Intl.NumberFormat("en-US", {
        style: "currency",
        currency: "USD",
        maximumFractionDigits: 8,
    });


    /*
     * CoinGecko OHLC candle format:
     *
     * [
     *     timestamp,
     *     open,
     *     high,
     *     low,
     *     close
     * ]
     */

    function normalizeCandles(values) {
        if (!Array.isArray(values)) {
            return [];
        }

        return values
            .filter((item) => {
                return Array.isArray(item) && item.length >= 5;
            })
            .map((item) => {
                return item
                    .slice(0, 5)
                    .map(Number);
            })
            .filter((item) => {
                return item.every(Number.isFinite);
            });
    }


    function prepareCanvas() {
        const ratio = Math.max(
            window.devicePixelRatio || 1,
            1
        );

        const width = Math.max(
            canvas.clientWidth,
            320
        );

        const height = Math.max(
            canvas.clientHeight,
            300
        );

        canvas.width = Math.round(width * ratio);
        canvas.height = Math.round(height * ratio);

        context.setTransform(
            ratio,
            0,
            0,
            ratio,
            0,
            0
        );

        context.clearRect(
            0,
            0,
            width,
            height
        );

        return {
            width,
            height,
        };
    }


    function drawMessage(message) {
        const dimensions = prepareCanvas();

        context.fillStyle = "#6b7280";
        context.font = "14px system-ui, sans-serif";
        context.textAlign = "center";

        context.fillText(
            message,
            dimensions.width / 2,
            dimensions.height / 2
        );
    }


    function drawChart() {
        const dimensions = prepareCanvas();
        const width = dimensions.width;
        const height = dimensions.height;

        if (candles.length < 2) {
            drawMessage(
                "Not enough OHLC candle data is available."
            );

            return;
        }

        const padding = {
            top: 20,
            right: 82,
            bottom: 34,
            left: 12,
        };

        const plotWidth =
            width -
            padding.left -
            padding.right;

        const plotHeight =
            height -
            padding.top -
            padding.bottom;

        const highest = Math.max(
            ...candles.map((item) => item[2])
        );

        const lowest = Math.min(
            ...candles.map((item) => item[3])
        );

        const rawRange =
            highest - lowest ||
            Math.max(
                highest * 0.01,
                0.00000001
            );

        const chartHigh =
            highest + rawRange * 0.06;

        const chartLow =
            lowest - rawRange * 0.06;

        const chartRange =
            chartHigh - chartLow;

        const slotWidth =
            plotWidth / candles.length;

        const candleWidth = Math.max(
            2,
            Math.min(
                slotWidth * 0.62,
                14
            )
        );

        const calculateY = (value) => {
            return (
                padding.top +
                (
                    (chartHigh - value) /
                    chartRange
                ) *
                plotHeight
            );
        };


        /*
         * Draw horizontal price grid.
         */

        context.font =
            "11px system-ui, sans-serif";

        context.lineWidth = 1;

        for (
            let index = 0;
            index <= 4;
            index += 1
        ) {
            const gridY =
                padding.top +
                (
                    plotHeight *
                    index /
                    4
                );

            const labelValue =
                chartHigh -
                (
                    chartRange *
                    index /
                    4
                );

            context.beginPath();

            context.moveTo(
                padding.left,
                gridY
            );

            context.lineTo(
                width - padding.right,
                gridY
            );

            context.strokeStyle = "#eef0f3";
            context.stroke();

            context.fillStyle = "#6b7280";
            context.textAlign = "left";

            context.fillText(
                usd.format(labelValue),
                width - padding.right + 8,
                gridY + 4
            );
        }


        /*
         * Draw OHLC candlesticks.
         *
         * Green: close is greater than or equal to open.
         * Red: close is lower than open.
         */

        candles.forEach(
            (item, index) => {
                const timestamp = item[0];
                const open = item[1];
                const high = item[2];
                const low = item[3];
                const close = item[4];

                const centerX =
                    padding.left +
                    slotWidth * index +
                    slotWidth / 2;

                const rising =
                    close >= open;

                const color = rising
                    ? "#198754"
                    : "#dc3545";

                const bodyTop = calculateY(
                    Math.max(open, close)
                );

                const bodyBottom = calculateY(
                    Math.min(open, close)
                );

                const bodyHeight = Math.max(
                    bodyBottom - bodyTop,
                    1
                );


                /*
                 * High/low wick.
                 */

                context.beginPath();

                context.moveTo(
                    centerX,
                    calculateY(high)
                );

                context.lineTo(
                    centerX,
                    calculateY(low)
                );

                context.strokeStyle = color;
                context.lineWidth = 1;
                context.stroke();


                /*
                 * Open/close candle body.
                 */

                context.fillStyle = color;

                context.fillRect(
                    centerX - candleWidth / 2,
                    bodyTop,
                    candleWidth,
                    bodyHeight
                );

                void timestamp;
            }
        );


        /*
         * Draw first and last dates.
         */

        const firstDate = new Date(
            candles[0][0]
        );

        const lastDate = new Date(
            candles[candles.length - 1][0]
        );

        context.fillStyle = "#6b7280";

        context.textAlign = "left";

        context.fillText(
            firstDate.toLocaleDateString(),
            padding.left,
            height - 10
        );

        context.textAlign = "right";

        context.fillText(
            lastDate.toLocaleDateString(),
            width - padding.right,
            height - 10
        );
    }


    async function loadChart() {
        status.textContent =
            "Loading live candlestick data…";

        try {
            const response = await fetch(
                `${endpoint}?days=${selectedDays}`,
                {
                    method: "GET",

                    headers: {
                        Accept: "application/json",
                    },

                    cache: "no-store",
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    "Market data request failed."
                );
            }

            candles = normalizeCandles(
                data.candles
            );

            if (!candles.length) {
                throw new Error(
                    "The provider returned no OHLC candles."
                );
            }

            drawChart();

            const latestCandle =
                candles[candles.length - 1];

            const latestClose =
                latestCandle[4];

            if (price) {
                price.textContent =
                    usd.format(latestClose);
            }

            if (updated) {
                updated.textContent =
                    `Live update: ${
                        new Date()
                            .toLocaleTimeString()
                    }`;
            }

            status.textContent =
                `${candles.length} real OHLC candles` +
                ` · Latest close ${
                    usd.format(latestClose)
                }`;
        } catch (error) {
            candles = [];

            drawMessage(
                "Candlestick data unavailable."
            );

            status.textContent =
                error instanceof Error
                    ? error.message
                    : "Candlestick data unavailable.";
        }
    }


    /*
     * Change candlestick date range.
     */

    buttons.forEach((button) => {
        button.addEventListener(
            "click",
            () => {
                selectedDays = Number(
                    button.dataset.days
                );

                buttons.forEach((item) => {
                    const isActive =
                        item === button;

                    item.classList.toggle(
                        "active",
                        isActive
                    );

                    item.setAttribute(
                        "aria-pressed",
                        String(isActive)
                    );
                });

                loadChart();
            }
        );
    });


    /*
     * Redraw without another network request
     * when the browser changes size.
     */

    window.addEventListener(
        "resize",
        () => {
            window.clearTimeout(
                resizeTimer
            );

            resizeTimer =
                window.setTimeout(
                    drawChart,
                    120
                );
        },
        {
            passive: true,
        }
    );


    /*
     * Initial load and one-minute refresh.
     */

    loadChart();

    refreshTimer = window.setInterval(
        loadChart,
        60000
    );

    window.addEventListener(
        "pagehide",
        () => {
            window.clearInterval(
                refreshTimer
            );

            window.clearTimeout(
                resizeTimer
            );
        }
    );
}());