// Update displayed values when sliders move
document.getElementById('layer1').addEventListener('input', (e) => {
    document.getElementById('layer1-value').textContent = e.target.value;
});

document.getElementById('layer2').addEventListener('input', (e) => {
    document.getElementById('layer2-value').textContent = e.target.value;
});

document.getElementById('bottleneck').addEventListener('input', (e) => {
    document.getElementById('bottleneck-value').textContent = e.target.value;
});

document.getElementById('layers').addEventListener('input', (e) => {
    document.getElementById('layers-value').textContent = e.target.value;
});

document.getElementById('l2').addEventListener('input', (e) => {
    document.getElementById('l2-value').textContent = parseFloat(e.target.value).toFixed(4);
});

document.getElementById('dropout').addEventListener('input', (e) => {
    document.getElementById('dropout-value').textContent = parseFloat(e.target.value).toFixed(2);
});

document.getElementById('sigma').addEventListener('input', (e) => {
    document.getElementById('sigma-value').textContent = parseFloat(e.target.value).toFixed(1);
});

document.getElementById('percentile').addEventListener('input', (e) => {
    document.getElementById('percentile-value').textContent = e.target.value;
});

document.getElementById('lr').addEventListener('input', (e) => {
    document.getElementById('lr-value').textContent = parseFloat(e.target.value).toFixed(4);
});

document.getElementById('batch').addEventListener('input', (e) => {
    document.getElementById('batch-value').textContent = e.target.value;
});

document.getElementById('epochs').addEventListener('input', (e) => {
    document.getElementById('epochs-value').textContent = e.target.value;
});

document.getElementById('filters').addEventListener('input', (e) => {
    document.getElementById('filters-value').textContent = e.target.value;
});

document.getElementById('kernel').addEventListener('input', (e) => {
    document.getElementById('kernel-value').textContent = e.target.value;
});

document.getElementById('heads').addEventListener('input', (e) => {
    document.getElementById('heads-value').textContent = e.target.value;
});

// Toggle convolutional settings
document.getElementById('conv-enable').addEventListener('change', (e) => {
    document.getElementById('conv-settings').style.display = e.target.checked ? 'block' : 'none';
});

// Connect to WebSocket for real-time updates
const socket = io();

socket.on('loss_update', (data) => {
    document.getElementById('val-loss').textContent = data.loss.toFixed(4);
    document.getElementById('detection-rate').textContent = data.detection_rate.toFixed(1) + '%';
    document.getElementById('false-pos').textContent = data.false_positives.toFixed(1) + '%';
    document.getElementById('train-time').textContent = data.time.toFixed(1) + 's';
    
    // Update chart
    updateChart(data.loss_history);
});

let lossChart = null;

function updateChart(lossHistory) {
    const ctx = document.getElementById('lossChart').getContext('2d');
    
    if (lossChart) {
        lossChart.destroy();
    }
    
    lossChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: lossHistory.map((_, i) => i),
            datasets: [{
                label: 'Training Loss',
                data: lossHistory,
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Test configuration
document.getElementById('test-btn').addEventListener('click', () => {
    const config = getConfig();
    fetch('/test_config', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(config)
    })
    .then(response => response.json())
    .then(data => {
        alert('Test complete! Check performance metrics.');
    });
});

// Start training
document.getElementById('train-btn').addEventListener('click', () => {
    const config = getConfig();
    fetch('/start_training', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(config)
    })
    .then(response => response.json())
    .then(data => {
        alert('Training started! Watch real-time updates.');
    });
});

// Export model
document.getElementById('export-btn').addEventListener('click', () => {
    fetch('/export_model', {
        method: 'POST'
    })
    .then(response => response.blob())
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'autoencoder_model.zip';
        a.click();
    });
});

function getConfig() {
    return {
        architecture: {
            layer1: parseInt(document.getElementById('layer1').value),
            layer2: parseInt(document.getElementById('layer2').value),
            bottleneck: parseInt(document.getElementById('bottleneck').value),
            layers: parseInt(document.getElementById('layers').value)
        },
        regularization: {
            l2: parseFloat(document.getElementById('l2').value),
            dropout: parseFloat(document.getElementById('dropout').value)
        },
        threshold: {
            sigma: parseFloat(document.getElementById('sigma').value),
            percentile: parseInt(document.getElementById('percentile').value)
        },
        convolutional: {
            enabled: document.getElementById('conv-enable').checked,
            filters: parseInt(document.getElementById('filters').value),
            kernel: parseInt(document.getElementById('kernel').value)
        },
        attention: {
            self: document.getElementById('self-attention').checked,
            cross: document.getElementById('cross-attention').checked,
            heads: parseInt(document.getElementById('heads').value)
        },
        training: {
            learning_rate: parseFloat(document.getElementById('lr').value),
            batch_size: parseInt(document.getElementById('batch').value),
            epochs: parseInt(document.getElementById('epochs').value)
        }
    };
}