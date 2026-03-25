document.addEventListener("DOMContentLoaded", () => {
    // -------------------------
    // Canvas Network Animation
    // -------------------------
    const canvas = document.getElementById('network-canvas');
    if (canvas) {
        initCanvasAnimation(canvas);
    }

    // -------------------------
    // Dashboard Logic
    // -------------------------
    const tableBody = document.getElementById('live-packet-table');
    if (tableBody) {
        // Initialize Socket.io
        const socket = io();

        // Chart Init
        let attackChart, activityChart;
        [attackChart, activityChart] = initCharts();

        // Data Models for charts
        const attackStats = {
            'Normal': 0, 
            'DDoS Attack (TCP-SYN Flood)': 0, 
            'Web Attack (XSS Injection)': 0, 
            'Brute Force (RDP/SSH)': 0, 
            'Backdoor (C2 Trojan Call)': 0, 
            'Exploit (Remote Code Execution)': 0
        };
        const protocolStats = {
            'TCP': 0, 'UDP': 0, 'HTTP': 0, 'HTTPS': 0, 'ICMP': 0
        };

        socket.on('new_packet', (packet) => {
            // Update Table
            const row = document.createElement('tr');
            
            // CSS classes for styling malicious packets
            let rowClass = packet.is_malicious ? 'row-malicious' : 'row-normal';
            row.className = `new-row ${rowClass}`;

            row.innerHTML = `
                <td>${packet.timestamp}</td>
                <td>${packet.protocol}</td>
                <td><span style="font-size:0.78em; color:#00a2ff;">${packet.osi_layer || 'N/A'}</span></td>
                <td>${packet.severity || 'N/A'}</td>
                <td>${packet.source_ip}</td>
                <td>${packet.destination_ip}</td>
                <td class="confidence-cell">${packet.confidence}%</td>
                <td>
                    ${packet.is_malicious 
                        ? '<span class="alert-badge">⚠ ' + packet.attack_type + '</span>' 
                        : '<span class="secure-badge">✓ Clean</span>'}
                </td>
            `;

            tableBody.prepend(row);

            // Keep only latest 100 rows to prevent lag
            if (tableBody.children.length > 50) {
                tableBody.removeChild(tableBody.lastChild);
            }

            // Remove animation class after 1s
            setTimeout(() => {
                row.classList.remove('new-row');
            }, 1000);

            // Update Charts
            updateCharts(packet, attackStats, protocolStats, attackChart, activityChart);

            // Update Threat Banner
            const threatLabel = document.getElementById('current-threat-label');
            const threatBox = document.getElementById('threat-indicator-box');
            const threatMeta = document.getElementById('threat-meta-info');

            if (packet.is_malicious) {
                threatLabel.innerText = `ALERT: ${packet.attack_type.toUpperCase()}`;
                threatLabel.className = 'threat-display malicious-text';
                threatBox.className = 'threat-alert-banner glass-panel attack-pulse';
                threatMeta.innerText = `Severity: ${packet.severity} | Source: ${packet.source_ip} | Confidence: ${packet.confidence}%`;
                
                // Keep alert for 15 seconds, then reset to clean state
                clearTimeout(window.threatResetTimer);
                window.threatResetTimer = setTimeout(() => {
                    threatLabel.innerText = "NO THREATS DETECTED";
                    threatLabel.className = "threat-display";
                    threatBox.className = "threat-alert-banner glass-panel";
                    threatMeta.innerText = "System Scanning Clean...";
                }, 15000);
            }
        });
    }
});

// -------------------------
// Chart.js Setup
// -------------------------
function initCharts() {
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.font.family = "'Inter', sans-serif";

    // Attack Distribution (Pie)
    const ctxPie = document.getElementById('attackPieChart').getContext('2d');
    const attackChart = new Chart(ctxPie, {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'DDoS', 'XSS', 'Brute Force', 'Backdoor', 'Exploit'],
            datasets: [{
                data: [1, 0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(0, 255, 170, 0.6)',  // Normal - Green
                    'rgba(255, 51, 102, 0.6)',  // DDoS - Red
                    'rgba(255, 165, 0, 0.6)',   // XSS - Orange
                    'rgba(147, 51, 234, 0.6)',  // Brute Force - Purple
                    'rgba(239, 68, 68, 0.6)',   // Backdoor - Dark Red
                    'rgba(0, 162, 255, 0.6)'    // Exploit - Blue
                ],
                borderColor: 'transparent',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right' }
            }
        }
    });

    // Network Activity (Bar)
    const ctxBar = document.getElementById('activityBarChart').getContext('2d');
    const activityChart = new Chart(ctxBar, {
        type: 'bar',
        data: {
            labels: ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP'],
            datasets: [{
                label: 'Packets Count by Protocol',
                data: [0, 0, 0, 0, 0],
                backgroundColor: 'rgba(0, 162, 255, 0.6)',
                borderColor: 'rgba(0, 162, 255, 1)',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { grid: { color: 'rgba(255,255,255,0.05)' } }
            }
        }
    });

    return [attackChart, activityChart];
}

function updateCharts(packet, attackStats, protocolStats, attackChart, activityChart) {
    // Attack Pie Chart Update: Map long technical names to the short display labels
    const originalCategories = [
        'Normal', 
        'DDoS Attack (TCP-SYN Flood)', 
        'Web Attack (XSS Injection)', 
        'Brute Force (RDP/SSH)', 
        'Backdoor (C2 Trojan Call)', 
        'Exploit (Remote Code Execution)'
    ];

    if (attackStats[packet.attack_type] !== undefined) {
        attackStats[packet.attack_type]++;
        // Ensure data stays aligned with the labels ['Normal', 'DDoS', 'XSS', 'Brute Force', 'Backdoor', 'Exploit']
        attackChart.data.datasets[0].data = originalCategories.map(cat => attackStats[cat]);
        attackChart.update();
    }

    // Protocol Bar Chart Update
    if (protocolStats[packet.protocol] !== undefined) {
        protocolStats[packet.protocol]++;
        const protocolLabels = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP'];
        activityChart.data.datasets[0].data = protocolLabels.map(proto => protocolStats[proto]);
        activityChart.update();
    }
}

// -------------------------
// Home Canvas Animation 
// -------------------------
function initCanvasAnimation(canvas) {
    const ctx = canvas.getContext('2d');
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = canvas.parentElement.clientHeight;

    const particles = [];
    const colors = ['#00ffaa', '#00a2ff', '#ffffff'];

    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.vx = (Math.random() - 0.5) * 1.5;
            this.vy = (Math.random() - 0.5) * 1.5;
            this.size = Math.random() * 2 + 1;
            this.color = colors[Math.floor(Math.random() * colors.length)];
        }
        update() {
            this.x += this.vx;
            this.y += this.vy;
            if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
            if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
        }
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fillStyle = this.color;
            ctx.fill();
        }
    }

    // Generate Particles
    for (let i = 0; i < 80; i++) particles.push(new Particle());

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        // Connect Particles
        for (let i = 0; i < particles.length; i++) {
            particles[i].update();
            particles[i].draw();
            for (let j = i; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 100) {
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(0, 255, 170, ${1 - dist/100})`;
                    ctx.lineWidth = 0.5;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(animate);
    }
    
    animate();
    
    // Resize Handle
    window.addEventListener('resize', () => {
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = canvas.parentElement.clientHeight;
    });
}
