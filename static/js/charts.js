document.addEventListener('DOMContentLoaded', function () {

    let hourlyChart = null;
    let weeklyChart = null;

    function createHorizontalOptions() {
        return {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,

            layout: {
                padding: { top: 10, bottom: 16, left: 12, right: 12 }
            },

            plugins: {
                legend: {
                    position: "top",
                    labels: {
                        color: "#e5e7eb",
                        font: { size: 11 },
                        boxWidth: 12,
                        boxHeight: 12,
                        padding: 14
                    }
                },
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.dataset.label}: ${ctx.parsed.x}`
                    }
                }
            },

            scales: {
                x: {
                    min: 0,
                    max: 1000,
                    beginAtZero: true,
                    ticks: {
                        color: "#9ca3af",
                        font: { size: 10 },
                        stepSize: 100,
                        padding: 8
                    },
                    grid: { color: "rgba(255,255,255,0.04)" }
                },

                y: {
                    offset: true,
                    ticks: {
                        color: "#9ca3af",
                        font: {
                            size: 9,
                            lineHeight: 0.7
                        },
                        padding: 2,
                        autoSkip: false,
                        maxRotation: 0,
                        minRotation: 0
                    },
                    grid: {
                        display: false
                    }
                }
            }
        };
    }

    /* ===============================
       HOURLY CHART
    =============================== */
    function renderHourlyChart(labels, alertValues, dropValues) {
        const ctx = document.getElementById('hourlyChart')?.getContext('2d');
        if (!ctx) return;

        if (hourlyChart) hourlyChart.destroy();

        hourlyChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels,
                datasets: [
                    {
                        label: "Alert",
                        data: alertValues,
                        backgroundColor: "rgba(255, 102, 0, 1)",
                        borderColor: "rgba(255, 102, 0, 1)",
                        borderWidth: 1.5,
                        borderRadius: 6,
                        maxBarThickness: 18
                    },
                    {
                        label: "Drop",
                        data: dropValues,
                        backgroundColor: "rgba(255, 0, 0, 1)",
                        borderColor: "rgba(255, 0, 0, 1)",
                        borderWidth: 1.5,
                        borderRadius: 6,
                        maxBarThickness: 18
                    }
                ]
            },
            options: createHorizontalOptions()
        });
    }

    /* ===============================
       WEEKLY CHART
    =============================== */
    function renderWeeklyChart(labels, alertValues, dropValues) {
        const ctx = document.getElementById('weeklyChart')?.getContext('2d');
        if (!ctx) return;

        if (weeklyChart) weeklyChart.destroy();

        weeklyChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels,
                datasets: [
                    {
                        label: "Alert",
                        data: alertValues,
                        backgroundColor: "rgba(255, 102, 0, 1)",
                        borderColor: "rgba(255, 102, 0, 1)",
                        borderWidth: 1.5,
                        borderRadius: 6,
                        maxBarThickness: 18
                    },
                    {
                        label: "Drop",
                        data: dropValues,
                        backgroundColor: "rgba(255, 0, 0, 1)",
                        borderColor: "rgba(255, 0, 0, 1)",
                        borderWidth: 1.5,
                        borderRadius: 6,
                        maxBarThickness: 18
                    }
                ]
            },
            options: createHorizontalOptions()
        });
    }

    /* ===============================
       UPDATE DASHBOARD
    =============================== */
    async function updateDashboard() {
        try {
            const res = await fetch(window.dashboardApiUrl);
            const data = await res.json();

            document.getElementById('threats-count').textContent = data.total_alerts || 0;
            document.getElementById('rules-count').textContent = data.total_rules || 0;
            document.getElementById('whitelist-count').textContent = data.total_ip_whitelist || 0;
            document.getElementById('blocklist-count').textContent = data.total_ip_blocklist || 0;

            /* =============================
               HOURLY → DIBALIK
            ============================== */
            if (data.alert_hour_labels) {
                const revLabels = [...data.alert_hour_labels].reverse();
                const revAlert = [...data.alert_hour_alert].reverse();
                const revDrop = [...data.alert_hour_drop].reverse();

                renderHourlyChart(
                    revLabels,
                    revAlert,
                    revDrop
                );
            }

            /* =============================
               WEEKLY → DIBALIK
            ============================== */
            if (data.alert_week_labels) {
                const revWeekLabels = [...data.alert_week_labels].reverse();
                const revWeekAlert = [...data.alert_week_alert].reverse();
                const revWeekDrop = [...data.alert_week_drop].reverse();

                renderWeeklyChart(
                    revWeekLabels,
                    revWeekAlert,
                    revWeekDrop
                );
            }

        } catch (err) {
            console.error("Dashboard API error:", err);
        }
    }

    updateDashboard();
    setInterval(updateDashboard, 5000);
});
