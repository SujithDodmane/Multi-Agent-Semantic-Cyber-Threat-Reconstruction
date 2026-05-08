/**
 * AEGIS — Cytoscape.js Graph Client
 *
 * Connects to the AEGIS Graph Service via WebSocket and renders
 * the threat knowledge graph in real time.
 *
 * Features:
 *   - CoSE-Bilkent layout (primary, force-directed clusters)
 *   - BFS layout (secondary, timeline DAG)
 *   - Incremental delta application (never re-render full graph)
 *   - Node color by threat_score
 *   - Edge labels with MITRE technique IDs
 *
 * Ref: Methodology §4.2 — Knowledge Graph Construction
 */

// ─── Initialize Cytoscape ─────────────────────────────────────────────────

const cy = cytoscape({
    container: document.getElementById('cy'),
    style: [
        {
            selector: 'node',
            style: {
                'label': 'data(label)',
                'background-color': 'data(color)',
                'shape': 'data(shape)',
                'width': 40,
                'height': 40,
                'font-size': '11px',
                'font-family': 'Inter, sans-serif',
                'font-weight': 500,
                'text-valign': 'bottom',
                'text-halign': 'center',
                'text-margin-y': 8,
                'color': '#e0e0e0',
                'text-outline-width': 2,
                'text-outline-color': '#0a0e17',
                'border-width': 2,
                'border-color': '#1a2332',
                'transition-property': 'background-color, width, height',
                'transition-duration': '0.3s',
            }
        },
        {
            selector: 'node:selected',
            style: {
                'border-width': 3,
                'border-color': '#00d4ff',
                'width': 50,
                'height': 50,
            }
        },
        {
            selector: 'edge',
            style: {
                'label': 'data(label)',
                'width': 2,
                'line-color': '#2a3a4a',
                'target-arrow-color': '#2a3a4a',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'font-size': '9px',
                'font-family': 'JetBrains Mono, monospace',
                'color': '#607080',
                'text-rotation': 'autorotate',
                'text-margin-y': -8,
            }
        },
        {
            selector: 'edge:selected',
            style: {
                'line-color': '#00d4ff',
                'target-arrow-color': '#00d4ff',
                'width': 3,
            }
        },
        {
            selector: 'node[label = "unknown"]',
            style: {
                'border-style': 'dashed',
                'border-width': 2,
                'border-color': '#607080',
                'background-color': '#1a2332',
                'opacity': 0.6,
                'color': '#8090a0',
                'label': 'unresolved entity'
            }
        },
    ],
    layout: { name: 'preset' },
    wheelSensitivity: 0.3,
});

// ─── Layout Configuration ─────────────────────────────────────────────────

/**
 * CoSE-Bilkent layout — primary.
 * Ref: §4.2 — "naturally clusters related nodes (e.g., an IP, the process
 * connecting to it, and the user running that process will cluster together)"
 */
const COSE_OPTIONS = {
    name: 'cose-bilkent',
    animate: 'end',
    animationDuration: 500,
    nodeRepulsion: 8000,
    idealEdgeLength: 120,
    edgeElasticity: 0.45,
    nestingFactor: 0.1,
    gravity: 0.25,
    numIter: 2500,
    tile: true,
    fit: true,
    padding: 40,
};

/**
 * BFS layout — secondary toggle.
 * Ref: §4.2 — "The BFS layout is appropriate for the timeline view
 * (a directed acyclic graph showing event sequence)"
 */
const BFS_OPTIONS = {
    name: 'breadthfirst',
    animate: true,
    animationDuration: 500,
    directed: true,
    spacingFactor: 1.5,
    fit: true,
    padding: 40,
};

let currentLayout = 'cose';

function runLayout(type) {
    currentLayout = type;
    const opts = type === 'bfs' ? BFS_OPTIONS : COSE_OPTIONS;
    cy.layout(opts).run();

    // Update button states
    document.getElementById('btn-layout-cose').classList.toggle('active', type === 'cose');
    document.getElementById('btn-layout-bfs').classList.toggle('active', type === 'bfs');
}

// ─── WebSocket Connection ─────────────────────────────────────────────────

let ws = null;
let reconnectAttempts = 0;

function connectWebSocket() {
    const wsUrl = `ws://${window.location.hostname}:${window.location.port}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        document.getElementById('ws-status').textContent = 'Connected';
        document.getElementById('stat-status').classList.add('connected');
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
        document.getElementById('ws-status').textContent = 'Disconnected';
        document.getElementById('stat-status').classList.remove('connected');

        // Auto-reconnect with backoff
        reconnectAttempts++;
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
        console.log(`[AEGIS] Reconnecting in ${delay}ms...`);
        setTimeout(connectWebSocket, delay);
    };

    ws.onerror = (err) => {
        console.error('[AEGIS] WebSocket error:', err);
    };

    // Keepalive ping every 30s
    setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
        }
    }, 30000);
}

// ─── Graph Update Handlers ────────────────────────────────────────────────

/**
 * Handle full graph load (on initial connection).
 */
function handleFullGraph(data) {
    cy.elements().remove();

    const elements = data.elements || {};
    const nodes = elements.nodes || [];
    const edges = elements.edges || [];

    cy.add([...nodes, ...edges]);
    updateStats(data.total_nodes || 0, data.total_edges || 0);

    if (nodes.length > 0) {
        runLayout(currentLayout);
    }

    console.log(`[AEGIS] Full graph loaded: ${nodes.length} nodes, ${edges.length} edges`);
}

/**
 * Handle incremental delta (new/updated nodes and edges).
 * Ref: §4.2 — "The browser client maintains its own copy of the full graph
 * and applies deltas incrementally."
 */
function handleDelta(data) {
    let changed = false;

    // Add new nodes
    const newNodes = data.new_nodes || [];
    for (const node of newNodes) {
        if (!cy.getElementById(node.data.id).length) {
            cy.add(node);
            changed = true;

            // Flash animation for new nodes
            const addedNode = cy.getElementById(node.data.id);
            addedNode.animate({
                style: { 'width': 60, 'height': 60 },
                duration: 300,
            }).animate({
                style: { 'width': 40, 'height': 40 },
                duration: 300,
            });
        }
    }

    // Update existing nodes
    const updatedNodes = data.updated_nodes || [];
    for (const node of updatedNodes) {
        const existing = cy.getElementById(node.data.id);
        if (existing.length) {
            existing.data(node.data);
            // Pulse animation
            existing.animate({
                style: { 'border-color': '#00d4ff', 'border-width': 4 },
                duration: 200,
            }).animate({
                style: { 'border-color': '#1a2332', 'border-width': 2 },
                duration: 500,
            });
        }
    }

    // Add new edges
    const newEdges = data.new_edges || [];
    for (const edge of newEdges) {
        if (!cy.getElementById(edge.data.id).length) {
            cy.add(edge);
            changed = true;
        }
    }

    // Re-layout if new elements were added
    if (changed && cy.elements().length > 0) {
        runLayout(currentLayout);
    }

    updateStats(data.total_nodes || cy.nodes().length, data.total_edges || cy.edges().length);
}

function updateStats(nodes, edges) {
    document.getElementById('node-count').textContent = nodes;
    document.getElementById('edge-count').textContent = edges;
}

// ─── Node Detail Panel ───────────────────────────────────────────────────

cy.on('tap', 'node', (event) => {
    const node = event.target;
    const data = node.data();

    const panel = document.getElementById('detail-panel');
    const body = document.getElementById('detail-body');
    const title = document.getElementById('detail-title');

    title.textContent = `${data.type.toUpperCase()}: ${data.label}`;
    body.innerHTML = `
        <div class="detail-row"><span>Type:</span> <code>${data.type}</code></div>
        <div class="detail-row"><span>Threat Score:</span> <span class="score-badge" style="background:${data.color}">${data.threat_score}</span></div>
        <div class="detail-row"><span>Risk Level:</span> ${data.risk_level}</div>
        <div class="detail-row"><span>First Seen:</span> <code>${data.first_seen || '—'}</code></div>
        <div class="detail-row"><span>Last Seen:</span> <code>${data.last_seen || '—'}</code></div>
    `;
    panel.classList.remove('hidden');
});

cy.on('tap', (event) => {
    if (event.target === cy) {
        document.getElementById('detail-panel').classList.add('hidden');
    }
});

document.getElementById('detail-close').addEventListener('click', () => {
    document.getElementById('detail-panel').classList.add('hidden');
});

// ─── Button Handlers ─────────────────────────────────────────────────────

document.getElementById('btn-layout-cose').addEventListener('click', () => runLayout('cose'));
document.getElementById('btn-layout-bfs').addEventListener('click', () => runLayout('bfs'));
document.getElementById('btn-fit').addEventListener('click', () => cy.fit(null, 40));
document.getElementById('btn-clear').addEventListener('click', () => {
    cy.elements().remove();
    updateStats(0, 0);
});

// ─── Start ───────────────────────────────────────────────────────────────

connectWebSocket();
