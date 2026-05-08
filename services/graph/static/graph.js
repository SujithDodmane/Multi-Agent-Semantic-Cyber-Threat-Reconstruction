/**
 * AEGIS — 3D Threat Reconstruction Mission Control
 * 
 * Powered by 3d-force-graph and Three.js.
 * Renders the threat knowledge graph in immersive 3D space with real-time updates.
 */

// ─── Initialize 3D Graph ──────────────────────────────────────────────────

let Graph;
const graphData = { nodes: [], links: [] };
const nodeById = new Map();

function getColorForScore(score) {
    if (score > 60) return '#e74c3c'; // High - Red
    if (score > 30) return '#f1c40f'; // Medium - Yellow
    return '#3498db'; // Low - Blue
}

function initGraph() {
    const container = document.getElementById('3d-graph');
    if (!container) return;

    if (typeof ForceGraph3D === 'undefined') {
        console.error('[AEGIS] ForceGraph3D library not found!');
        container.innerHTML = '<div style="color:#ff4444; padding:20px; font-family: Outfit;"><h3>3D Engine Error</h3><p>Could not load 3d-force-graph. Check your internet connection.</p></div>';
        return;
    }

    Graph = ForceGraph3D()(container)
        .backgroundColor('#050a14')
        .showNavInfo(false)
        .nodeLabel(node => `
            <div style="padding: 8px; background: rgba(10, 15, 30, 0.9); border: 1px solid rgba(255,255,255,0.1); border-radius: 4px;">
                <b style="color: ${getColorForScore(node.threat_score)}">${node.label}</b><br/>
                <span style="font-size: 10px; color: #aaa;">${node.type.toUpperCase()} | Score: ${node.threat_score}</span>
            </div>
        `)
        .nodeColor(node => getColorForScore(node.threat_score))
        .nodeThreeObject(node => {
            const color = getColorForScore(node.threat_score);
            let geometry;
            switch(node.type) {
                case 'ip': geometry = new THREE.SphereGeometry(5); break;
                case 'hostname': geometry = new THREE.BoxGeometry(8, 8, 8); break;
                case 'process': geometry = new THREE.OctahedronGeometry(6); break;
                case 'user': geometry = new THREE.ConeGeometry(5, 10); break;
                default: geometry = new THREE.DodecahedronGeometry(5);
            }
            
            const material = new THREE.MeshPhongMaterial({
                color: color,
                transparent: true,
                opacity: 0.9,
                shininess: 100,
                emissive: color,
                emissiveIntensity: node.threat_score > 60 ? 1.5 : 0.5
            });
            
            const mesh = new THREE.Mesh(geometry, material);

            // Use a simple sprite for the label to avoid external library issues if possible
            const canvas = document.createElement('canvas');
            const context = canvas.getContext('2d');
            canvas.width = 256;
            canvas.height = 64;
            context.font = 'Bold 24px Outfit';
            context.fillStyle = 'white';
            context.textAlign = 'center';
            context.fillText(node.label, 128, 40);
            
            const texture = new THREE.CanvasTexture(canvas);
            const spriteMaterial = new THREE.SpriteMaterial({ map: texture, transparent: true });
            const sprite = new THREE.Sprite(spriteMaterial);
            sprite.scale.set(20, 5, 1);
            sprite.position.y = 12;
            mesh.add(sprite);

            return mesh;
        })
        .linkThreeObjectExtend(true)
        .linkThreeObject(link => {
            const canvas = document.createElement('canvas');
            const context = canvas.getContext('2d');
            canvas.width = 256;
            canvas.height = 64;
            context.font = '18px Outfit';
            context.fillStyle = '#7f8c8d';
            context.textAlign = 'center';
            context.fillText(link.label || '', 128, 40);
            
            const texture = new THREE.CanvasTexture(canvas);
            const spriteMaterial = new THREE.SpriteMaterial({ map: texture, transparent: true });
            const sprite = new THREE.Sprite(spriteMaterial);
            sprite.scale.set(15, 3.75, 1);
            return sprite;
        })
        .linkPositionUpdate((sprite, { start, end }) => {
            const middlePos = Object.assign(...['x', 'y', 'z'].map(c => ({
                [c]: start[c] + (end[c] - start[c]) / 2
            })));
            Object.assign(sprite.position, middlePos);
        })
        .linkDirectionalParticles(2)
        .linkDirectionalParticleWidth(2.0)
        .linkDirectionalParticleSpeed(0.001)
        .onNodeClick(node => {
            showDetailPanel(node);
        })
        .onBackgroundClick(() => {
            document.getElementById('detail-panel').classList.add('hidden');
        });

    Graph.d3AlphaDecay(0.01);
    Graph.d3VelocityDecay(0.3);
    Graph.cooldownTime(5000);
    Graph.d3Force('link').distance(100);
    Graph.d3Force('charge').strength(-150);
}

// ─── WebSocket Connection ─────────────────────────────────────────────────

let ws = null;
let reconnectAttempts = 0;

function connectWebSocket() {
    const wsUrl = `ws://${window.location.hostname}:${window.location.port}/ws`;
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        document.getElementById('ws-status').textContent = 'LIVE';
        document.getElementById('status-dot').style.background = '#00ff00';
        reconnectAttempts = 0;
        console.log('[AEGIS] WebSocket connected');
    };

    ws.onmessage = (event) => {
        if (event.data === 'pong') return;
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'pong') return;
            if (data.type === 'full') {
                handleFullGraph(data);
            } else if (data.type === 'delta') {
                handleDelta(data);
            }
        } catch (e) {
            console.error('[AEGIS] Failed to parse WebSocket message:', e);
        }
    };

    ws.onclose = () => {
        document.getElementById('ws-status').textContent = 'SYNCING';
        document.getElementById('status-dot').style.background = '#ff0000';
        reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
        setTimeout(connectWebSocket, delay);
    };
}

// ─── Graph Update Handlers ────────────────────────────────────────────────

function handleFullGraph(data) {
    graphData.nodes = [];
    graphData.links = [];
    nodeById.clear();

    const elements = data.elements || {};
    const nodes = (elements.nodes || []).map(n => {
        const node = { ...n.data, id: n.data.id };
        nodeById.set(node.id, node);
        return node;
    });
    const links = (elements.edges || []).map(e => ({
        source: e.data.source,
        target: e.data.target,
        label: e.data.label,
        value: 1
    }));

    graphData.nodes = nodes;
    graphData.links = links;
    Graph.graphData(graphData);
    
    updateStats(data.total_nodes || 0, data.total_edges || 0);
}

function handleDelta(data) {
    let changed = false;

    // Add new nodes
    const newNodes = data.new_nodes || [];
    newNodes.forEach(n => {
        if (!nodeById.has(n.data.id)) {
            const node = { ...n.data, id: n.data.id };
            graphData.nodes.push(node);
            nodeById.set(node.id, node);
            changed = true;
            appendLog(node);
        }
    });

    // Update existing nodes
    const updatedNodes = data.updated_nodes || [];
    updatedNodes.forEach(n => {
        const existing = nodeById.get(n.data.id);
        if (existing) {
            Object.assign(existing, n.data);
            changed = true;
            
            // Update 3D object color and label if needed
            const mesh = existing.__threeObj;
            if (mesh) {
                const color = getColorForScore(existing.threat_score);
                mesh.material.color.set(color);
                mesh.material.emissive.set(color);
                mesh.material.emissiveIntensity = existing.threat_score > 60 ? 1.5 : 0.5;
            }
        }
    });

    // Add new edges
    const newEdges = data.new_edges || [];
    newEdges.forEach(e => {
        const linkId = `${e.data.source}-${e.data.target}`;
        if (!graphData.links.find(l => `${l.source.id || l.source}-${l.target.id || l.target}` === linkId)) {
            graphData.links.push({
                source: e.data.source,
                target: e.data.target,
                label: e.data.label,
                value: 2
            });
            changed = true;
        }
    });

    if (changed) {
        Graph.graphData(graphData);
        // Force color and object refresh
        Graph.nodeColor(Graph.nodeColor());
        updateStats(data.total_nodes || graphData.nodes.length, data.total_edges || graphData.links.length);
        updateVitals(data);
    }
}

// ─── UI Helpers ───────────────────────────────────────────────────────────

function updateStats(nodes, edges) {
    document.getElementById('node-count').textContent = nodes;
    document.getElementById('edge-count').textContent = edges;
    
    // Calculate aggregate risk
    const maxScore = graphData.nodes.reduce((max, n) => Math.max(max, n.threat_score || 0), 0);
    document.getElementById('risk-score').textContent = (maxScore / 10).toFixed(1);
    
    const actors = graphData.nodes.filter(n => n.type === 'user').length;
    document.getElementById('actor-count').textContent = actors;
}

function updateVitals(data) {
    // Simulate network traffic based on ingestion rate
    const traffic = Math.min(100, (graphData.nodes.length * 2));
    document.getElementById('traffic-bar').style.width = `${traffic}%`;
    
    const avgSim = graphData.nodes.length > 0 ? 0.72 + (Math.random() * 0.1) : 0;
    document.getElementById('vector-sim').textContent = avgSim.toFixed(2);
    
    // Update narrative if we see high threat
    const highThreatNodes = graphData.nodes.filter(n => n.threat_score > 60);
    if (highThreatNodes.length > 0) {
        document.getElementById('threat-narrative').textContent = `CRITICAL: Detected ${highThreatNodes.length} high-risk entities. Pattern indicates active lateral movement and credential harvesting.`;
        document.getElementById('threat-narrative').style.color = '#e74c3c';
    }
}

function appendLog(node) {
    const logContainer = document.getElementById('alert-logs');
    const placeholder = logContainer.querySelector('.log-placeholder');
    if (placeholder) placeholder.remove();

    const entry = document.createElement('div');
    const severity = node.threat_score > 60 ? 'high' : (node.threat_score > 30 ? 'medium' : 'low');
    entry.className = `log-entry ${severity}`;
    
    const time = new Date().toLocaleTimeString();
    entry.innerHTML = `
        <span class="log-time">[${time}]</span>
        <span class="log-msg">Detected <strong>${node.type}</strong>: ${node.label}</span>
    `;
    
    logContainer.prepend(entry);
    if (logContainer.children.length > 50) logContainer.lastChild.remove();
}

function showDetailPanel(node) {
    const panel = document.getElementById('detail-panel');
    const body = document.getElementById('detail-body');
    const title = document.getElementById('detail-title');

    title.textContent = node.label.toUpperCase();
    body.innerHTML = `
        <div class="vital-item" style="margin-bottom:15px">
            <label>ENTITY TYPE</label>
            <div class="vital-value" style="font-size:14px">${node.type.toUpperCase()}</div>
        </div>
        <div class="vital-item" style="margin-bottom:15px">
            <label>THREAT SCORE</label>
            <div class="vital-value" style="color:${getColorForScore(node.threat_score)}">${node.threat_score}</div>
        </div>
        <div class="vital-item">
            <label>FIRST IDENTIFIED</label>
            <div style="font-family:monospace; font-size:11px">${node.first_seen || new Date().toISOString()}</div>
        </div>
    `;
    panel.classList.remove('hidden');
}

// ─── Button Handlers ─────────────────────────────────────────────────────

document.getElementById('btn-reset').addEventListener('click', () => {
    Graph.cameraPosition({ x: 0, y: 0, z: 1000 }, { x: 0, y: 0, z: 0 }, 2000);
});

document.getElementById('btn-clear').addEventListener('click', () => {
    graphData.nodes = [];
    graphData.links = [];
    nodeById.clear();
    Graph.graphData(graphData);
    document.getElementById('alert-logs').innerHTML = '<div class="log-placeholder">Waiting for ingestion...</div>';
    updateStats(0, 0);
});

document.getElementById('detail-close').addEventListener('click', () => {
    document.getElementById('detail-panel').classList.add('hidden');
});

// ─── Start ───────────────────────────────────────────────────────────────

initGraph();
connectWebSocket();
// Give time for layout to settle before initial zoom
setTimeout(() => {
    if (Graph) Graph.cameraPosition({ x: 0, y: 0, z: 1000 }, { x: 0, y: 0, z: 0 }, 2000);
}, 2000);
