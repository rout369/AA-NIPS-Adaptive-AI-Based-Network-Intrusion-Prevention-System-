let connections = [];
let charts = {};

// Load data on page load
document.addEventListener('DOMContentLoaded', () => {
    loadData();
    setInterval(loadData, 5000); // Refresh every 5 seconds
    
    document.getElementById('refresh-btn').addEventListener('click', loadData);
    document.getElementById('filter-ip').addEventListener('input', filterTable);
    document.getElementById('filter-threat').addEventListener('change', filterTable);
    document.getElementById('filter-action').addEventListener('change', filterTable);
});

async function loadData() {
    await Promise.all([
        loadConnections(),
        loadStats()
    ]);
    document.getElementById('update-time').textContent = new Date().toLocaleTimeString();
}

async function loadConnections() {
    try {
        const response = await fetch('/api/connections');
        connections = await response.json();
        filterTable();
    } catch (error) {
        console.error('Error loading connections:', error);
    }
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        updateStats(stats);
        updateCharts(stats);
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

function updateStats(stats) {
    document.getElementById('total-conn').textContent = stats.total_connections;
    document.getElementById('total-allowed').textContent = stats.total_allowed;
    document.getElementById('total-blocked').textContent = stats.total_blocked;
    document.getElementById('feedback-count').textContent = stats.feedback_count;
}

function updateCharts(stats) {
    // Threat Distribution Chart
    const threatCtx = document.getElementById('threatChart').getContext('2d');
    if (charts.threat) charts.threat.destroy();
    
    charts.threat = new Chart(threatCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Suspicious', 'Monitor', 'Normal'],
            datasets: [{
                data: [
                    stats.threat_levels.CRITICAL,
                    stats.threat_levels.SUSPICIOUS,
                    stats.threat_levels.MONITOR,
                    stats.threat_levels.NORMAL
                ],
                backgroundColor: ['#ef4444', '#f59e0b', '#fbbf24', '#6b7280']
            }]
        }
    });

    // Feedback Chart
    const feedbackCtx = document.getElementById('feedbackChart').getContext('2d');
    if (charts.feedback) charts.feedback.destroy();
    
    charts.feedback = new Chart(feedbackCtx, {
        type: 'bar',
        data: {
            labels: ['False Positives', 'Missed Attacks', 'Correct'],
            datasets: [{
                data: [
                    stats.false_positives,
                    stats.missed_attacks,
                    stats.correct_detections
                ],
                backgroundColor: ['#f59e0b', '#ef4444', '#10b981']
            }]
        }
    });
}

function filterTable() {
    const ipFilter = document.getElementById('filter-ip').value.toLowerCase();
    const threatFilter = document.getElementById('filter-threat').value;
    const actionFilter = document.getElementById('filter-action').value;
    
    const filtered = connections.filter(conn => {
        if (ipFilter && !conn.source_ip.includes(ipFilter) && !conn.dest_ip.includes(ipFilter)) {
            return false;
        }
        if (threatFilter && conn.threat_level !== threatFilter) return false;
        if (actionFilter && conn.firewall_action !== actionFilter) return false;
        return true;
    });
    
    renderTable(filtered);
}

function renderTable(connections) {
    const tbody = document.getElementById('connections-table');
    tbody.innerHTML = '';
    
    connections.forEach(conn => {
        const row = document.createElement('tr');
        row.className = 'border-t border-gray-700 hover:bg-gray-700 cursor-pointer';
        row.onclick = () => showDetails(conn);
        
        const threatColor = {
            'CRITICAL': 'text-red-400',
            'SUSPICIOUS': 'text-orange-400',
            'MONITOR': 'text-yellow-400',
            'NORMAL': 'text-gray-400'
        }[conn.threat_level] || 'text-gray-400';
        
        const actionColor = conn.firewall_action === 'ALLOW' ? 'text-green-400' : 'text-red-400';
        
        row.innerHTML = `
            <td class="px-4 py-2">${new Date(conn.timestamp).toLocaleTimeString()}</td>
            <td class="px-4 py-2">${conn.source_ip}</td>
            <td class="px-4 py-2">${conn.dest_ip}</td>
            <td class="px-4 py-2">${conn.port}</td>
            <td class="px-4 py-2">${(conn.ml_score * 100).toFixed(1)}%</td>
            <td class="px-4 py-2 ${threatColor}">${conn.threat_level}</td>
            <td class="px-4 py-2 ${actionColor}">${conn.firewall_action}</td>
            <td class="px-4 py-2">
                ${conn.feedback ? '✅' : '⏳'}
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

async function showDetails(conn) {
    try {
        const response = await fetch(`/api/connection/${conn.id}`);
        const details = await response.json();
        
        const modal = document.getElementById('detail-modal');
        const content = document.getElementById('modal-content');
        
        let modelScoresHtml = '';
        if (details.model_scores) {
            modelScoresHtml = '<h3 class="font-semibold mt-4 mb-2">Model Scores:</h3><div class="space-y-1">';
            for (const [model, score] of Object.entries(details.model_scores)) {
                const color = getScoreColor(score);
                modelScoresHtml += `<div class="flex justify-between">
                    <span>${model}:</span>
                    <span class="${color}">${(score * 100).toFixed(1)}%</span>
                </div>`;
            }
            modelScoresHtml += '</div>';
        }
        
        content.innerHTML = `
            <div class="space-y-3">
                <div class="grid grid-cols-2 gap-2">
                    <div><span class="text-gray-400">Time:</span> ${new Date(details.timestamp).toLocaleString()}</div>
                    <div><span class="text-gray-400">Protocol:</span> ${details.protocol}</div>
                    <div><span class="text-gray-400">Source:</span> ${details.source_ip}:${details.source_port}</div>
                    <div><span class="text-gray-400">Dest:</span> ${details.dest_ip}:${details.port}</div>
                </div>
                
                <div class="border-t border-gray-600 pt-3">
                    <div class="flex justify-between items-center">
                        <span class="text-gray-400">ML Score:</span>
                        <span class="text-xl font-bold ${getScoreColor(details.ml_score)}">
                            ${(details.ml_score * 100).toFixed(1)}%
                        </span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Threat Level:</span>
                        <span class="${getThreatColor(details.threat_level)}">${details.threat_level}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Consensus:</span>
                        <span>${details.consensus.toFixed(1)}% (${details.consensus_level})</span>
                    </div>
                </div>
                
                ${modelScoresHtml}
                
                <div class="border-t border-gray-600 pt-3">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Firewall Action:</span>
                        <span class="${details.firewall_action === 'ALLOW' ? 'text-green-400' : 'text-red-400'}">
                            ${details.firewall_action}
                        </span>
                    </div>
                    ${details.rule_id ? `<div class="flex justify-between">
                        <span class="text-gray-400">Rule:</span>
                        <span>${details.rule_id}</span>
                    </div>` : ''}
                    <div class="flex justify-between">
                        <span class="text-gray-400">DDoS Count:</span>
                        <span class="${details.ddos_limited ? 'text-red-400' : ''}">
                            ${details.ddos_count}/min
                        </span>
                    </div>
                </div>
                
                ${details.feedback ? `
                <div class="border-t border-gray-600 pt-3">
                    <h3 class="font-semibold mb-2">Feedback Given:</h3>
                    <div class="bg-gray-700 p-3 rounded">
                        <div class="text-sm text-gray-400">${new Date(details.feedback.timestamp).toLocaleString()}</div>
                        <div class="font-medium mt-1">${details.feedback.reason}</div>
                        ${details.feedback.comment ? `<div class="text-sm mt-1">"${details.feedback.comment}"</div>` : ''}
                    </div>
                </div>
                ` : `
                <div class="border-t border-gray-600 pt-3">
                    <h3 class="font-semibold mb-2">Give Feedback:</h3>
                    <div class="space-y-2">
                        <select id="feedback-reason" class="w-full bg-gray-700 text-white px-3 py-2 rounded">
                            <option value="false_positive">False Positive (should be normal)</option>
                            <option value="missed_attack">Missed Attack (should be blocked)</option>
                            <option value="correct">Correct Detection</option>
                        </select>
                        <input type="text" id="feedback-comment" placeholder="Optional comment..." 
                               class="w-full bg-gray-700 text-white px-3 py-2 rounded">
                        <button onclick="submitFeedback(${details.id})" 
                                class="w-full bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">
                            Submit Feedback
                        </button>
                    </div>
                </div>
                `}
            </div>
        `;
        
        modal.classList.remove('hidden');
        modal.classList.add('flex');
    } catch (error) {
        console.error('Error loading connection details:', error);
    }
}

async function submitFeedback(connectionId) {
    const reason = document.getElementById('feedback-reason').value;
    const comment = document.getElementById('feedback-comment').value;
    
    try {
        const response = await fetch('/api/feedback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                connection_id: connectionId,
                reason: reason,
                comment: comment
            })
        });
        
        if (response.ok) {
            alert('Feedback submitted successfully!');
            closeModal();
            loadData(); // Refresh data
        } else {
            alert('Failed to submit feedback');
        }
    } catch (error) {
        console.error('Error submitting feedback:', error);
        alert('Error submitting feedback');
    }
}

function closeModal() {
    const modal = document.getElementById('detail-modal');
    modal.classList.add('hidden');
    modal.classList.remove('flex');
}

function getScoreColor(score) {
    if (score >= 0.9) return 'text-red-400';
    if (score >= 0.75) return 'text-orange-400';
    if (score >= 0.5) return 'text-yellow-400';
    return 'text-gray-400';
}

function getThreatColor(threat) {
    const colors = {
        'CRITICAL': 'text-red-400',
        'SUSPICIOUS': 'text-orange-400',
        'MONITOR': 'text-yellow-400',
        'NORMAL': 'text-gray-400'
    };
    return colors[threat] || 'text-gray-400';
}