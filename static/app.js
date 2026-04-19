// Initialize Charts
const commonChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
        x: { display: false },
        y: { display: true, beginAtZero: true, max: 100, ticks: { color: '#8e99a8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
    },
    animation: false,
    elements: { point: { radius: 0 }, line: { tension: 0.4, borderWidth: 2 } }
};

let cpuData = Array(30).fill(0);
let memData = Array(30).fill(0);
let diskData = Array(30).fill(0);
let netData = Array(30).fill(0);
let labels = Array(30).fill('');

const ctxCpu = document.getElementById('cpuChart').getContext('2d');
const cpuChart = new Chart(ctxCpu, {
    type: 'line',
    data: { labels: labels, datasets: [{ data: cpuData, borderColor: '#3273f6', backgroundColor: 'rgba(50, 115, 246, 0.1)', fill: true }] },
    options: commonChartOptions
});

const ctxMem = document.getElementById('memChart').getContext('2d');
const memChart = new Chart(ctxMem, {
    type: 'line',
    data: { labels: labels, datasets: [{ data: memData, borderColor: '#a352cc', backgroundColor: 'rgba(163, 82, 204, 0.1)', fill: true }] },
    options: commonChartOptions
});

const ctxDisk = document.getElementById('diskChart').getContext('2d');
const diskChart = new Chart(ctxDisk, {
    type: 'line',
    data: { labels: labels, datasets: [{ data: diskData, borderColor: '#8ccb61', backgroundColor: 'rgba(140, 203, 97, 0.1)', fill: true }] },
    options: commonChartOptions
});

const ctxNet = document.getElementById('netChart').getContext('2d');
const netChart = new Chart(ctxNet, {
    type: 'line',
    data: { labels: labels, datasets: [{ data: netData, borderColor: '#3273f6', backgroundColor: 'rgba(50, 115, 246, 0.1)', fill: true }] },
    options: commonChartOptions
});

const ctxThreat = document.getElementById('threatGauge').getContext('2d');
const threatGauge = new Chart(ctxThreat, {
    type: 'doughnut',
    data: {
        datasets: [{
            data: [0, 100],
            backgroundColor: ['#e02f44', '#181b1f'],
            borderWidth: 0,
            circumference: 180,
            rotation: 270,
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '80%',
        animation: { animateRotate: true, animateScale: false },
        plugins: { tooltip: { enabled: false } }
    }
});

let networkInterval = null;

// UI Navigation
function showSection(id) {
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('nav ul li').forEach(el => el.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    
    // Highlight nav item if clicked from sidebar
    if (event && event.currentTarget && event.currentTarget.parentNode) {
        if (event.currentTarget.tagName === 'A') {
            event.currentTarget.parentNode.classList.add('active');
        }
    }
    
    // Clear network interval if not on network section
    if (networkInterval) {
        clearInterval(networkInterval);
        networkInterval = null;
    }

    if (id === 'history') {
        loadHistory();
    } else if (id === 'network') {
        loadNetwork();
        networkInterval = setInterval(loadNetwork, 3000);
    }
}

// WebSocket Connection
const ws = new WebSocket(`ws://${window.location.host}/ws`);
let lastProcessList = [];

let notifiedThreats = new Set();

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    updateMetrics(data.system, data.processes.length);
    updateThreatGauge(data.threats);
    updateTopMemoryProcesses(data.processes);
    updateNewWidgets(data.escalations, data.active_connections);
    lastProcessList = data.processes;
    renderProcessTable(data.processes);
    
    // Desktop Notification Logic
    let criticals = data.threats.filter(t => t.threat_severity === 'Critical');
    if (criticals.length > 0) {
        // If not looking at dashboard actively...
        if (!document.getElementById('dashboard').classList.contains('active')) {
            criticals.forEach(c => {
                if (!notifiedThreats.has(c.pid)) {
                    notifiedThreats.add(c.pid);
                    if ("Notification" in window && Notification.permission === "granted") {
                        new Notification("🚨 CRITICAL THREAT DETECTED", {
                            body: `Process ${c.name} (PID: ${c.pid}) flagged as Critical! Check Malviz Dashboard.`,
                        });
                    }
                }
            });
        }
    }
};

// Update Metrics and Charts
function updateMetrics(sys, procCount) {
    document.getElementById('top-total-procs').innerText = procCount;
    
    document.getElementById('cpu-value').innerText = `${sys.cpu.toFixed(1)}%`;
    document.getElementById('mem-value').innerText = `${sys.memory.toFixed(1)}%`;
    document.getElementById('disk-value').innerText = `${sys.disk.toFixed(1)}%`;
    document.getElementById('net-value').innerText = `${sys.network_mbs.toFixed(2)}`;
    
    cpuData.push(sys.cpu); cpuData.shift();
    memData.push(sys.memory); memData.shift();
    diskData.push(sys.disk); diskData.shift();
    netData.push(sys.network_mbs); netData.shift();
    
    cpuChart.update();
    memChart.update();
    diskChart.update();
    netChart.update();
}

function updateThreatGauge(threats) {
    let threatValue = 0;
    let rank = 'Normal';
    let color = '#8ccb61';
    
    if (threats.length > 0) {
        threatValue = Math.min(threats.length * 20, 100);
        const hasCritical = threats.some(t => t.threat_severity === 'Critical');
        if (hasCritical) {
            rank = 'Critical';
            color = '#e02f44';
            threatValue = Math.max(threatValue, 70);
        } else {
            rank = 'Warning';
            color = '#ff9830';
            threatValue = Math.max(threatValue, 40);
        }
    }
    
    const sc = document.getElementById('threat-score');
    sc.innerText = rank;
    sc.style.color = color;
    
    threatGauge.data.datasets[0].data = [threatValue, 100 - threatValue];
    threatGauge.data.datasets[0].backgroundColor[0] = color;
    threatGauge.update();
}

function updateTopMemoryProcesses(processes) {
    const memList = document.getElementById('top-mem-list');
    if (!memList) return;
    memList.innerHTML = '';
    const topProcs = [...processes].slice(0, 5);
    topProcs.forEach(p => {
        const li = document.createElement('li');
        li.style.marginBottom = '12px';
        li.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
        li.style.paddingBottom = '8px';
        
        let pathDisp = p.path ? p.path : '-';
        
        li.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <div><span style="display:inline-block; width:45px; color:#a352cc;">[${p.pid}]</span> <strong style="color:var(--text-main); font-family:var(--font-main);">${p.name}</strong></div>
                <button class="btn btn-small" style="padding: 2px 8px; font-size: 0.8em; background:#3273f6;" onclick='showDetails(${JSON.stringify(p).replace(/'/g, "&apos;")})'>Inspect 🔍</button>
            </div>
            <div style="font-size:0.85em; color:#6b7280; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${pathDisp}">${pathDisp}</div>
        `;
        memList.appendChild(li);
    });
}

let all_escalations = [];

async function loadInitialEscalations() {
    try {
        const res = await fetch('/api/escalations');
        all_escalations = await res.json();
        renderEscalations(all_escalations);
    } catch(e) { console.error('Failed to load escalations:', e); }
}
loadInitialEscalations();

function renderEscalations(escalationsArr) {
    const escList = document.getElementById('escalations-list');
    escList.innerHTML = '';
    if (!escalationsArr || escalationsArr.length === 0) {
        escList.innerHTML = '<li style="text-align:center; padding-top:40px; color:#6b7280;">No escalation attempts detected.</li>';
        return;
    }
    escalationsArr.forEach(e => {
        const li = document.createElement('li');
        li.style.marginBottom = '12px';
        li.style.borderBottom = '1px solid rgba(220, 38, 38, 0.2)';
        li.style.paddingBottom = '8px';
        li.innerHTML = `
            <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
                <strong style="color:var(--text-main); font-family:var(--font-main);"><span style="color:var(--accent-red);">${e.source}</span> ➔ ${e.target}</strong>
                <span style="color:#8e99a8; font-size: 0.85em;">${e.time}</span>
            </div>
            <div style="color: var(--accent-orange); margin-bottom: 4px;"><strong>Method:</strong> ${e.method}</div>
            <div style="color: #a5b4fc;"><strong>Shift:</strong> ${e.privilege}</div>
        `;
        escList.appendChild(li);
    });
}

function updateNewWidgets(new_escalations, active_connections) {
    if (new_escalations && new_escalations.length > 0) {
        let added = false;
        new_escalations.forEach(e => {
            // Deduplicate against existing 24h history
            let exists = all_escalations.find(x => x.source === e.source && x.target === e.target && x.method === e.method);
            if (!exists) {
                all_escalations.unshift(e); // push to top explicitly
                added = true;
            }
        });
        if(added) renderEscalations(all_escalations);
    }

    const connList = document.getElementById('active-conn-list');
    if (active_connections && active_connections.length > 0) {
        connList.innerHTML = '';
        active_connections.forEach(c => {
            const li = document.createElement('li');
            li.style.marginBottom = '12px';
            li.style.borderBottom = '1px dashed rgba(255, 255, 255, 0.1)';
            li.style.paddingBottom = '8px';
            
            let highlight = c.suspicious ? 'color: var(--accent-red); font-weight: bold;' : 'color: #8ccb61;';
            li.innerHTML = `
                <div style="display:flex; justify-content:space-between; margin-bottom: 4px;">
                    <strong style="color:var(--text-main); font-family:var(--font-main);">${c.process} <span style="color:#6b7280; font-size:0.8em;">[${c.pid}]</span></strong>
                    <span style="color:#8e99a8; font-size: 0.9em;">[${c.country}]</span>
                </div>
                <div style="font-family: var(--font-mono); display:flex; justify-content:space-between;">
                    <span style="color: #a5b4fc;">${c.ip}</span>
                    <span style="${highlight}">Port ${c.port}</span>
                </div>
            `;
            connList.appendChild(li);
        });
    } else {
        connList.innerHTML = '<li style="text-align:center; padding-top:40px; color:#6b7280;">No active external connections.</li>';
    }
}

// Render Process Table
function renderProcessTable(processes) {
    const tbody = document.getElementById('process-tbody');
    const searchTerm = document.getElementById('proc-search').value.toLowerCase();
    
    // Sort processes: Critical first, then Warning, then Normal. Then by PID.
    const severityRank = { "Critical": 0, "Warning": 1, "Normal": 2 };
    processes.sort((a, b) => {
        if (severityRank[a.threat_severity] !== severityRank[b.threat_severity]) {
            return severityRank[a.threat_severity] - severityRank[b.threat_severity];
        }
        return a.pid - b.pid;
    });

    tbody.innerHTML = '';
    
    processes.forEach(p => {
        if (searchTerm) {
            if (!p.name.toLowerCase().includes(searchTerm) && !p.pid.toString().includes(searchTerm)) {
                return;
            }
        }
        
        let pathDisp = p.path ? p.path : '-';
        if (pathDisp.length > 40) pathDisp = '...' + pathDisp.substring(pathDisp.length - 40);
        
        let scoreColor = p.threat_score >= 80 ? 'var(--accent-red)' : (p.threat_score >= 40 ? 'var(--accent-orange)' : 'var(--accent-green)');
        let scoreHtml = `
            <div style="display:flex; align-items:center; gap: 8px;">
                <strong style="color: ${scoreColor}; width: 35px;">[ ${p.threat_score} ]</strong>
                <div style="flex-grow:1; background: rgba(0,0,0,0.3); height: 6px; border-radius: 3px; border: 1px solid var(--panel-border);">
                    <div style="width: ${p.threat_score}%; background: ${scoreColor}; height: 100%; border-radius: 3px;"></div>
                </div>
            </div>
        `;
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${p.pid}</td>
            <td><strong>${p.name}</strong></td>
            <td>${p.username}</td>
            <td class="code-font" title="${p.path}">${pathDisp}</td>
            <td class="code-font" style="color:var(--accent-blue);">${p.ip || '-'}</td>
            <td style="min-width: 150px;">${scoreHtml}</td>
            <td><button class="btn btn-small" onclick='showDetails(${JSON.stringify(p).replace(/'/g, "&apos;")})'>Inspect</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function filterTable() {
    renderProcessTable(lastProcessList);
}

// Load History
async function loadHistory() {
    const res = await fetch('/api/history');
    const history = await res.json();
    const tbody = document.getElementById('history-tbody');
    tbody.innerHTML = '';
    
    history.forEach(row => {
        let badgeClass = 'bg-warning';
        if (row.threat_severity === 'Critical') badgeClass = 'bg-critical';
        
        let reasonsObj = [];
        try { reasonsObj = JSON.parse(row.reasons); } catch(e) {}
        
        let contextText = 'Heuristic match';
        if (reasonsObj.length > 0) {
            contextText = typeof reasonsObj[0] === 'string' ? reasonsObj[0] : (reasonsObj[0].short || reasonsObj[0].title);
        }
        
        if (contextText.length > 50) contextText = contextText.substring(0, 50) + '...';
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${new Date(row.timestamp).toLocaleString()}</td>
            <td>${row.pid}</td>
            <td>${row.name}</td>
            <td><span class="badge ${badgeClass}">${row.threat_severity}</span></td>
            <td class="code-font" style="color:#c7d0d9; font-size: 0.9em;">${contextText}</td>
            <td><button class="btn btn-small" onclick='showDetailsFromHistory(${JSON.stringify(row).replace(/'/g, "&apos;")})'>Deep Inspect</button></td>
        `;
        tbody.appendChild(tr);
    });
}

// Load Network
let fullNetworkData = [];

async function loadNetwork() {
    try {
        const res = await fetch('/api/network');
        fullNetworkData = await res.json();
        filterNetworkTable();
    } catch (e) {
        console.error("Failed to load network: ", e);
    }
}

function filterNetworkTable() {
    const tbody = document.getElementById('network-tbody');
    tbody.innerHTML = '';
    
    const filterVal = document.getElementById('net-protocol-filter')?.value || "ALL";
    
    fullNetworkData.forEach(c => {
        let proto = c.protocol.toUpperCase();
        if (filterVal !== "ALL" && proto !== filterVal) return;
        
        const tr = document.createElement('tr');
        
        // Assign class based on protocol for Wireshark aesthetics
        let rowClass = '';
        if (proto === 'TCP') rowClass = 'row-tcp';
        else if (proto === 'UDP') rowClass = 'row-udp';
        else if (proto === 'DNS') rowClass = 'row-dns';
        
        tr.className = rowClass;
        
        tr.innerHTML = `
            <td>${c.no}</td>
            <td>${c.time}</td>
            <td class="code-font">${c.source}</td>
            <td class="code-font">${c.destination}</td>
            <td><strong>${c.protocol}</strong></td>
            <td>${c.length}</td>
            <td>${c.info}</td>
        `;
        tr.style.cursor = 'pointer';
        tr.onclick = (e) => showPacketDetails(c, e.currentTarget);
        tbody.appendChild(tr);
    });
}

function showPacketDetails(c, rowEl) {
    document.getElementById('packet-details').style.display = 'block';
    
    // Highlight selected row visually
    document.querySelectorAll('#network-tbody tr').forEach(r => r.style.outline = 'none');
    if (rowEl) {
        rowEl.style.outline = '2px solid var(--accent-blue)';
        rowEl.style.outlineOffset = '-2px';
    }
    
    document.getElementById('pd-no').innerText = c.no;
    document.getElementById('pd-time').innerText = c.time;
    document.getElementById('pd-src').innerText = c.source;
    document.getElementById('pd-dst').innerText = c.destination;
    document.getElementById('pd-proto').innerText = c.protocol;
    document.getElementById('pd-len').innerText = c.length;
    document.getElementById('pd-info').innerText = c.info;
    document.getElementById('pd-hex').innerText = c.hex_dump || "No payload data available.";
}

let current_inspect_pid = null;

function inspectManual() {
    const term = document.getElementById('manual-sim-pid').value.trim();
    if (!term) return;
    
    let found = null;
    // Check if the input is a number (PID)
    if (!isNaN(term)) {
        const pId = parseInt(term, 10);
        found = lastProcessList.find(p => p.pid === pId);
        if (!found) {
            // Fallback for manually probing an unlisted PID
            showDetails({pid: pId, name: 'Manual Load', threat_severity: 'Unknown'});
            return;
        }
    } else {
        // Search by Process Name
        const termLower = term.toLowerCase();
        found = lastProcessList.find(p => p.name.toLowerCase().includes(termLower));
        if (!found) {
            alert("Could not find an active process matching that name.");
            return;
        }
    }
    
    showDetails(found);
}

function showDetails(p) {
    current_inspect_pid = p.pid;
    
    // Redirect to simulation directly bypass
    document.querySelectorAll('nav ul li').forEach(el => el.classList.remove('active'));
    document.querySelector('nav ul li:nth-child(3)').classList.add('active'); 
    
    showSection('simulation');

    // Populate Simulation Metadata
    document.getElementById('sim-container').style.display = 'block';
    
    document.getElementById('s-pid').innerText = p.pid;
    document.getElementById('s-name').innerText = p.name;
    document.getElementById('s-threat').innerText = p.threat_severity;
    document.getElementById('s-threat').className = 'badge ' + 
        (p.threat_severity === 'Critical' ? 'bg-critical' : (p.threat_severity === 'Warning' ? 'bg-warning' : 'bg-normal'));

    // Command Line Parsing
    const cmdlineEl = document.getElementById('s-cmdline');
    const decodeBtn = document.getElementById('s-cmdline-decode-btn');
    if (p.cmdline && p.cmdline.trim() !== "") {
        cmdlineEl.innerText = p.cmdline;
        cmdlineEl.dataset.original = p.cmdline;
        
        // Check if looks like encoded powershell or base64 flag
        const cmdLower = p.cmdline.toLowerCase();
        if (cmdLower.includes('-enc') || cmdLower.includes('-encodedcommand') || cmdLower.includes('base64')) {
            decodeBtn.style.display = 'inline-block';
            decodeBtn.innerText = 'Decode Base64';
        } else {
            decodeBtn.style.display = 'none';
        }
    } else {
        cmdlineEl.innerText = "No command line arguments detected.";
        decodeBtn.style.display = 'none';
    }

    // Populate Threat Detection Reasons
    const reasonsContainer = document.getElementById('s-reasons-container');
    const reasonsList = document.getElementById('s-reasons-list');
    
    let r_arr = [];
    if (Array.isArray(p.reasons)) r_arr = p.reasons;
    else if (typeof p.reasons === 'string') {
        try { r_arr = JSON.parse(p.reasons); } catch(e) {}
    }
    
    if (r_arr && r_arr.length > 0) {
        reasonsContainer.style.display = 'block';
        reasonsList.innerHTML = '';
        r_arr.forEach(reason => {
            const li = document.createElement('li');
            li.style.marginBottom = '15px';
            li.style.background = 'rgba(0,0,0,0.2)';
            li.style.padding = '12px';
            li.style.borderRadius = '4px';
            li.style.borderLeft = '3px solid var(--accent-red)';
            li.style.listStyle = 'none';
            
            if (typeof reason === 'string') {
                li.innerText = reason;
            } else {
                li.innerHTML = `
                    <div style="font-weight: 600; font-size: 1.1em; margin-bottom: 6px; color: var(--accent-red);">${reason.title}</div>
                    <div style="margin-bottom: 8px; color: #eaeaea; font-size: 0.95em;"><strong>Detected Anomaly:</strong> ${reason.short}</div>
                    <div style="margin-bottom: 12px; color: #8e99a8; font-size: 0.85em;"><strong>Deep Context:</strong> ${reason.detail}</div>
                    <div style="display: flex; gap: 10px; font-size: 0.85em; margin-bottom: 8px;">
                        <span style="background: rgba(163, 82, 204, 0.15); border: 1px solid rgba(163, 82, 204, 0.3); color: #c481e3; padding: 3px 8px; border-radius: 4px;"><strong>MITRE ATT&CK:</strong> ${reason.mitre || 'T1059'}</span>
                    </div>
                    <div style="margin-top: 8px; color: var(--accent-orange); font-size: 0.85em; background: rgba(255, 152, 48, 0.05); padding: 8px; border-radius: 4px; border: 1px dashed rgba(255, 152, 48, 0.2);">
                        <strong>PoC Execution / CVE Link:</strong> <br/><code style="color:var(--text-main);">${reason.poc || 'No explicit PoC loaded.'}</code>
                    </div>
                `;
            }
            reasonsList.appendChild(li);
        });
    } else {
        reasonsContainer.style.display = 'none';
        reasonsList.innerHTML = '';
    }

    // Clear Simulation panes
    document.getElementById('syscall-log').innerHTML = '';
    document.getElementById('sim-network-tbody').innerHTML = '';
    document.getElementById('m-ram').innerText = '';
    document.getElementById('m-exports').innerHTML = '';
    document.getElementById('m-imports').innerHTML = '';
    document.getElementById('m-imports').innerHTML = '';
    document.getElementById('m-peheaders').innerHTML = '';
    document.getElementById('action-status').innerText = '';
    document.getElementById('m-strings').style.display = 'none';
    
    startSimulation(current_inspect_pid);
    fetchDeepAnalysis(current_inspect_pid);
}

function showDetailsFromHistory(row) {
    // Process JSON strings back to objects
    try { row.reasons = JSON.parse(row.reasons); } catch(e) { row.reasons = []; }
    try { row.network_connections = JSON.parse(row.network_connections); } catch(e) { row.network_connections = []; }
    
    showDetails(row);
}

function switchModalTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
    
    event.target.classList.add('active');
    document.getElementById(`tab-${tabId}`).style.display = 'block';
    
    if (tabId === 'deep' || tabId === 'imports') {
        fetchDeepAnalysis(current_inspect_pid);
    }
}

async function fetchDeepAnalysis(pid) {
    const loading = document.getElementById('deep-loading');
    const errBlock = document.getElementById('deep-error');
    const resultsBlock = document.getElementById('deep-results');
    
    if (!pid) return;
    
    loading.style.display = 'block';
    errBlock.style.display = 'none';
    resultsBlock.style.display = 'none';
    
    try {
        const res = await fetch('/api/inspect/' + pid);
        const data = await res.json();
        
        loading.style.display = 'none';
        
        if (!data.success) {
            errBlock.innerText = data.error || 'Unknown analysis error';
            errBlock.style.display = 'block';
            return;
        }
        
        document.getElementById('m-ram').innerText = data.ram_usage_mb.toFixed(2);
        document.getElementById('m-hash').innerText = data.sha256 || "Unknown";
        
        let tokenHtml = `<strong>Integrity Level:</strong> ${data.tokens?.integrity || "Unknown"}<br/><br/><strong>Enabled Privileges:</strong><br/>`;
        if (data.tokens?.privileges && data.tokens.privileges.length > 0) {
            tokenHtml += data.tokens.privileges.map(p => `• ${p}`).join('<br/>');
        } else {
            tokenHtml += `<i>None detected...</i>`;
        }
        if (data.tokens?.error) tokenHtml += `<br/><br/><span style="color:var(--accent-red)">Error: ${data.tokens.error}</span>`;
        document.getElementById('m-tokens').innerHTML = tokenHtml;

        let handleHtml = `<strong>Loaded DLLs (${data.handles?.dlls?.length || 0}):</strong><br/>`;
        if(data.handles?.dlls) handleHtml += data.handles.dlls.slice(0, 20).join('<br/>') + (data.handles.dlls.length > 20 ? '<br/>... (truncated)' : '') + '<br/><br/>';
        
        handleHtml += `<strong>Open Files (${data.handles?.files?.length || 0}):</strong><br/>`;
        if(data.handles?.files) handleHtml += data.handles.files.slice(0, 20).join('<br/>') + (data.handles.files.length > 20 ? '<br/>... (truncated)' : '') + '<br/><br/>';

        handleHtml += `<strong>Open Sockets (${data.handles?.sockets?.length || 0}):</strong><br/>`;
        if(data.handles?.sockets) handleHtml += data.handles.sockets.join('<br/>');

        document.getElementById('m-handles').innerHTML = handleHtml;
        
        // Format Imports
        let importsText = '';
        if (data.imports && Object.keys(data.imports).length > 0) {
            for (const dll in data.imports) {
                importsText += `[${dll}]\n`;
                data.imports[dll].forEach(func => {
                    importsText += `  └─ ${func}\n`;
                });
            }
        } else {
            importsText = 'No imported functions detected or accessible.';
        }
        document.getElementById('m-imports').innerText = importsText;
        
        // Format Exports
        let exportsText = '';
        if (data.exports && data.exports.length > 0) {
            data.exports.forEach(func => {
                exportsText += `• ${func}\n`;
            });
        } else {
            exportsText = 'No exported functions detected.';
        }
        document.getElementById('m-exports').innerText = exportsText;
        
        // Format PE Headers Side-by-Side
        const peContainer = document.getElementById('m-peheaders');
        peContainer.innerHTML = '';
        if (data.pe_headers && Object.keys(data.pe_headers).length > 0) {
            for (const section in data.pe_headers) {
                const sectionData = data.pe_headers[section];
                
                const wrapper = document.createElement('div');
                wrapper.style.marginBottom = '25px';
                
                const title = document.createElement('h5');
                title.innerText = `--- [ ${section} ] ---`;
                title.style.color = '#3273f6';
                title.style.margin = '0 0 10px 0';
                title.style.fontSize = '1.1em';
                wrapper.appendChild(title);
                
                const splitView = document.createElement('div');
                splitView.style.display = 'flex';
                splitView.style.gap = '20px';
                splitView.style.alignItems = 'stretch';
                
                // Left: Struct
                const structView = document.createElement('div');
                structView.style.flex = '1';
                structView.style.backgroundColor = '#0b0c10';
                structView.style.padding = '10px';
                structView.style.borderRadius = '5px';
                structView.style.border = '1px solid #1f2328';
                structView.className = 'code-font';
                structView.style.whiteSpace = 'pre-wrap'; // wrap is better for tight spaces
                structView.style.overflow = 'visible'; 
                structView.innerText = sectionData.struct || 'N/A';
                
                // Right: Hex
                const hexView = document.createElement('div');
                hexView.style.flex = '2';
                hexView.style.backgroundColor = '#0b0c10';
                hexView.style.padding = '10px';
                hexView.style.borderRadius = '5px';
                hexView.style.border = '1px solid #1f2328';
                hexView.className = 'code-font';
                hexView.style.whiteSpace = 'pre';
                hexView.style.overflow = 'visible'; 
                hexView.innerText = sectionData.hex || 'N/A';
                
                splitView.appendChild(structView);
                splitView.appendChild(hexView);
                
                wrapper.appendChild(splitView);
                peContainer.appendChild(wrapper);
            }
        } else {
            peContainer.innerHTML = '<p>No PE binary headers mapped.</p>';
        }
        
        resultsBlock.style.display = 'block';
        
    } catch (e) {
        loading.style.display = 'none';
        errBlock.innerText = 'Failed to fetch deep analysis API: ' + e;
        errBlock.style.display = 'block';
    }
}

let simInterval = null;

async function startSimulation(pid) {
    document.getElementById('sim-status').innerText = `Streaming active trace for PID ${pid}...`;
    
    if (simInterval) clearInterval(simInterval);
    
    const fetchSim = async () => {
        if (!current_inspect_pid || current_inspect_pid !== pid) return;
        try {
            const res = await fetch('/api/simulate/' + pid);
            const data = await res.json();
            
            if (data.error) {
                document.getElementById('sim-status').innerText = 'Simulation Error: ' + data.error;
                return;
            }
            
            // Render Syscalls
            const sLog = document.getElementById('syscall-log');
            if (data.syscalls) {
                data.syscalls.forEach(call => {
                    const line = document.createElement('div');
                    // simple parsing of my artificial timestamp format "[12:34:56.789] NtApi -> SUCCESS"
                    if(call.includes("SUCCESS")) {
                        line.innerHTML = call.replace(/\[(.*?)\]/, '<span class="log-time">[$1]</span>').replace('SUCCESS', '<span class="log-success">SUCCESS</span>');
                    } else {
                        line.innerHTML = call.replace(/\[(.*?)\]/, '<span class="log-time">[$1]</span>').replace(/(STATUS_\w+)/, '<span class="log-fail">$1</span>');
                    }
                    sLog.appendChild(line);
                });
                sLog.scrollTop = sLog.scrollHeight;
            }
            
            // Render Net
            const tbody = document.getElementById('sim-network-tbody');
            tbody.innerHTML = '';
            if (data.network && data.network.length > 0) {
                data.network.forEach(n => {
                    const tr = document.createElement('tr');
                    tr.className = n.protocol === 'TCP' ? 'row-tcp' : 'row-udp';
                    tr.innerHTML = `
                        <td>${n.protocol}</td>
                        <td class="code-font">${n.local}</td>
                        <td class="code-font">${n.remote}</td>
                        <td>${n.state}</td>
                    `;
                    tbody.appendChild(tr);
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#8e99a8;">No active network connections</td></tr>';
            }
            
        } catch (e) {
            console.error(e);
        }
    };
    
    fetchSim();
    simInterval = setInterval(fetchSim, 2000);
}

function downloadReport() {
    if (!current_inspect_pid) {
        alert("No process selected for report.");
        return;
    }
    
    const pid = document.getElementById('s-pid').innerText;
    const name = document.getElementById('s-name').innerText;
    const threat = document.getElementById('s-threat').innerText;
    
    const reasonsNode = document.getElementById('s-reasons-list');
    const reasons = reasonsNode && reasonsNode.innerText.trim() !== '' ? reasonsNode.innerText : "No anomaly signatures matched.";
    const exportsText = document.getElementById('m-exports').innerText || "None";
    const importsText = document.getElementById('m-imports').innerText || "None";
    const peText = document.getElementById('m-peheaders').innerText || "None";
    
    const syscallNode = document.getElementById('syscall-log');
    let syscallText = syscallNode.innerText || "No syscalls captured.";
    
    const networkRows = document.querySelectorAll('#sim-network-tbody tr');
    let netText = "";
    networkRows.forEach(tr => {
        netText += tr.innerText.replace(/\t/g, '    ') + "\n";
    });
    if (!netText.trim() || netText.includes("No active network connections")) {
        netText = "No active network connections.";
    }
    
    const reportContent = `Malviz Forensic Report
==============================
PID: ${pid}
Name: ${name}
Threat Severity: ${threat}
Time: ${new Date().toLocaleString()}

--- Threat Detection Report & Context ---
${reasons}

--- Deep Memory & PE Analysis ---
Actual RAM Usage: ${document.getElementById('m-ram').innerText} MB

Exported Functions:
${exportsText}

Imported APIs:
${importsText}

PE Binary Analysis:
${peText}

--- Syscall Trace ---
${syscallText}

--- Process Network Traffic ---
${netText}
`;

    const blob = new Blob([reportContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `malviz_report_pid_${pid}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function openVT() {
    const hash = document.getElementById('m-hash').innerText;
    if (hash && hash !== 'Unknown') {
        window.open(`https://www.virustotal.com/gui/search/${hash}`, '_blank');
    } else {
        alert("Hash is unknown, cannot search VirusTotal.");
    }
}

async function performAction(action) {
    if (!current_inspect_pid) return;
    const statusEl = document.getElementById('action-status');
    statusEl.style.color = '#c7d0d9';
    statusEl.innerText = `Executing ${action}...`;
    try {
        const res = await fetch(`/api/action/${action}/${current_inspect_pid}`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            statusEl.style.color = 'var(--accent-green)';
            statusEl.innerText = `${action} successful.`;
        } else {
            statusEl.style.color = 'var(--accent-red)';
            statusEl.innerText = `Failed: ${data.error}`;
        }
    } catch(e) {
        statusEl.style.color = 'var(--accent-red)';
        statusEl.innerText = `Error: ${e}`;
    }
    setTimeout(() => { statusEl.innerText = ''; }, 3000);
}

function downloadDump() {
    if (!current_inspect_pid) return;
    window.location.href = `/api/dump/${current_inspect_pid}`;
}

async function fetchStrings() {
    if (!current_inspect_pid) return;
    const stringBox = document.getElementById('m-strings');
    stringBox.style.display = 'block';
    stringBox.innerText = 'Extracting strings...';
    try {
        const res = await fetch(`/api/strings/${current_inspect_pid}`);
        const data = await res.json();
        if (data.error) {
            stringBox.innerText = `Error: ${data.error}`;
        } else if (data.strings && data.strings.length > 0) {
            stringBox.innerText = data.strings.join('\\n');
        } else {
            stringBox.innerText = 'No strings found.';
        }
    } catch(e) {
        stringBox.innerText = `Error fetching strings: ${e}`;
    }
}

function decodeCmdline() {
    const cmdlineEl = document.getElementById('s-cmdline');
    const original = cmdlineEl.dataset.original;
    if (!original) return;
    
    // Simple heuristic to extract base64 chunk from commands like -enc <base64>
    // Powershell base64 is utf-16le encoded, but we'll do a best-effort decode in JS
    
    const parts = original.split(/\s+/);
    let decodedStr = original;
    
    parts.forEach(part => {
        // Look for long base64-like strings in the arguments
        if (part.length > 20 && /^[a-zA-Z0-9+/]+={0,2}$/.test(part)) {
            try {
                // Default base64 decode
                let rawStr = atob(part);
                // Attempt to strip null bytes if it was utf-16le PS encoding
                rawStr = rawStr.replace(/\0/g, ''); 
                
                decodedStr = decodedStr.replace(part, `\n\n[DECODED_PAYLOAD]\n${rawStr}\n[/DECODED_PAYLOAD]\n\n`);
            } catch(e) {
                // Not valid base64, ignore
            }
        }
    });

    cmdlineEl.innerText = decodedStr;
    document.getElementById('s-cmdline-decode-btn').style.display = 'none'; // Hide after decoding
}
