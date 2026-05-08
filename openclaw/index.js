/**
 * AEGIS — OpenClaw Gateway Entry Point
 * 
 * Initializes the OpenClaw orchestration framework:
 * - Loads HEARTBEAT.md (continuous SOC monitoring loop)
 * - Registers SKILL.md agents (Triage, Correlation, Timeline)
 * - Configures Protocol Adapters (Telegram, Discord)
 * - Sets up credential vault from environment variables
 * 
 * Architecture: Node.js for I/O (orchestration, messaging, WebSockets)
 *              Python for Math (embeddings, vector search, LLM inference)
 * 
 * Ref: Methodology §2.1 — HEARTBEAT.md Configuration
 * Ref: Methodology §2.3 — OpenClaw RBAC & Credential Vault
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const yaml = require('js-yaml') || null;
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

// ─── Configuration from Environment ─────────────────────────────────────────

const config = {
  // Python FastAPI service endpoints (credential vault)
  ingestionApiUrl: process.env.INGESTION_API_URL || 'http://localhost:8000',
  embeddingServiceUrl: process.env.EMBEDDING_SERVICE_URL || 'http://localhost:8001',
  correlationServiceUrl: process.env.CORRELATION_SERVICE_URL || 'http://localhost:8003',
  synthesizerServiceUrl: process.env.SYNTHESIZER_SERVICE_URL || 'http://localhost:8004',

  // Notification + Graph service endpoints
  notificationServiceUrl: process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:8005',
  graphServiceUrl: process.env.GRAPH_SERVICE_URL || 'http://localhost:5000',
  telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '',
  telegramChatId: process.env.TELEGRAM_CHAT_ID || '',
  discordWebhookUrl: process.env.DISCORD_WEBHOOK_URL || '',

  // Heartbeat config
  pollIntervalMs: parseInt(process.env.HEARTBEAT_POLL_MS || '500', 10),
  httpTimeoutMs: parseInt(process.env.HTTP_TIMEOUT_MS || '5000', 10),

  // Circuit breaker
  failureThreshold: 3,
  recoveryTimeoutMs: 60000,
};

// ─── Cognitive RAM (file-backed key-value store) ─────────────────────────────

const COGNITIVE_RAM_DIR = path.join(__dirname, '..', 'data', 'cognitive_ram');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function cognitiveRamWrite(key, value) {
  ensureDir(COGNITIVE_RAM_DIR);
  const safeKey = key.replace(/[:/]/g, '_');
  const filePath = path.join(COGNITIVE_RAM_DIR, `${safeKey}.json`);
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function cognitiveRamRead(key) {
  const safeKey = key.replace(/[:/]/g, '_');
  const filePath = path.join(COGNITIVE_RAM_DIR, `${safeKey}.json`);
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

function cognitiveRamDelete(key) {
  const safeKey = key.replace(/[:/]/g, '_');
  const filePath = path.join(COGNITIVE_RAM_DIR, `${safeKey}.json`);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
}

// ─── IP Activity Counters (4-hour TTL) ──────────────────────────────────────

function getHourBucket() {
  return Math.floor(Date.now() / (3600 * 1000));
}

function incrementIpCounter(ip) {
  if (!ip) return;
  const bucket = getHourBucket();
  const key = `activity_ip_${ip}_${bucket}`;
  const current = cognitiveRamRead(key) || { count: 0, expires: bucket + 4 };
  current.count += 1;
  cognitiveRamWrite(key, current);
}

function getIpActivityScore(ip) {
  if (!ip) return 0;
  const currentBucket = getHourBucket();
  let totalCount = 0;
  // Check last 4 hour buckets
  for (let offset = 0; offset < 4; offset++) {
    const key = `activity_ip_${ip}_${currentBucket - offset}`;
    const data = cognitiveRamRead(key);
    if (data && data.count) {
      totalCount += data.count;
    }
  }
  return totalCount > 0 ? 20 : 0; // +20 points if IP seen recently
}

// ─── Threat Lists ───────────────────────────────────────────────────────────

let threatLists = {
  dangerous_processes: [],
  c2_ports: [],
  severity_thresholds: { P0: 61, P1: 41, P2: 21, BENIGN: 0 },
  scoring_weights: {},
};

function loadThreatLists() {
  try {
    const configPath = path.join(__dirname, 'config', 'threat_lists.yaml');
    const content = fs.readFileSync(configPath, 'utf-8');
    // Simple YAML parsing (key: value and list items)
    const lines = content.split('\n');
    let currentKey = null;
    let currentList = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('#') || !trimmed) continue;

      if (!trimmed.startsWith('-') && trimmed.includes(':')) {
        if (currentKey && currentList.length > 0) {
          threatLists[currentKey] = [...currentList];
          currentList = [];
        }
        const parts = trimmed.split(':');
        currentKey = parts[0].trim();
        const value = parts.slice(1).join(':').trim();
        if (value && !value.startsWith('#')) {
          // Scalar value
          const numVal = Number(value);
          if (!isNaN(numVal)) {
            if (!threatLists[currentKey]) threatLists[currentKey] = {};
            // This handles nested keys like severity_thresholds
          }
        }
      } else if (trimmed.startsWith('-') && currentKey) {
        let val = trimmed.substring(1).trim().split('#')[0].trim();
        const numVal = Number(val);
        currentList.push(isNaN(numVal) ? val : numVal);
      }
    }
    if (currentKey && currentList.length > 0) {
      threatLists[currentKey] = currentList;
    }

    console.log(`[AEGIS] Loaded threat lists: ${threatLists.dangerous_processes.length} dangerous processes, ${threatLists.c2_ports.length} C2 ports`);
  } catch (e) {
    console.error(`[AEGIS] Failed to load threat lists: ${e.message}`);
  }
}

// ─── Triage Scoring (Pure Computation) ──────────────────────────────────────

const WEB_SERVERS = ['apache2', 'apache2.exe', 'nginx', 'nginx.exe', 'w3wp.exe', 'tomcat', 'httpd', 'httpd.exe'];
const CMD_SHELLS = ['cmd.exe', 'powershell.exe', 'bash', 'sh'];

function triageScore(entry) {
  let score = 0;
  const flags = [];

  const processName = (entry.process_name || '').toLowerCase();
  const parentProcess = (entry.parent_process_name || '').toLowerCase();
  const destPort = entry.dest_port;
  const eventType = entry.event_type || '';

  // Condition 1: Dangerous process (+40)
  if (threatLists.dangerous_processes.some(p => processName.includes(p.toLowerCase()))) {
    score += 40;
    flags.push(`dangerous_process:${processName}`);
  }

  // Condition 2: Web server parent + cmd child (+35)
  if (WEB_SERVERS.includes(parentProcess) && CMD_SHELLS.includes(processName)) {
    score += 35;
    flags.push(`webshell:${parentProcess}->${processName}`);
  }

  // Condition 3: C2 port (+30)
  if (destPort && threatLists.c2_ports.includes(destPort)) {
    score += 30;
    flags.push(`c2_port:${destPort}`);
  }

  // Condition 4: Critical event types (+50)
  if (['PRIVILEGE_ESCALATION', 'EXFILTRATION_HINT'].includes(eventType)) {
    score += 50;
    flags.push(`critical_event:${eventType}`);
  }

  // Condition 5: IP historical correlation (+20)
  const ipScore = getIpActivityScore(entry.source_ip) + getIpActivityScore(entry.dest_ip);
  if (ipScore > 0) {
    score += 20;
    flags.push('ip_historical_correlation');
  }

  // Update IP counters
  incrementIpCounter(entry.source_ip);
  incrementIpCounter(entry.dest_ip);

  // Classify severity
  let severity = 'BENIGN';
  let correlationRequired = false;
  if (score >= 61) { severity = 'P0'; correlationRequired = true; }
  else if (score >= 41) { severity = 'P1'; correlationRequired = true; }
  else if (score >= 21) { severity = 'P2'; correlationRequired = false; }

  return {
    anomaly_detected: score > 20,
    severity,
    heuristic_flags: flags,
    correlation_required: correlationRequired,
    confidence: Math.min(score / 100, 1.0),
    score,
  };
}

// ─── HTTP Helper ────────────────────────────────────────────────────────────

function httpGet(url, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`Timeout after ${timeoutMs}ms`));
    }, timeoutMs);

    http.get(url, (res) => {
      clearTimeout(timeout);
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`JSON parse error: ${e.message}`)); }
      });
    }).on('error', (e) => {
      clearTimeout(timeout);
      reject(e);
    });
  });
}

function httpPost(url, body, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const postData = JSON.stringify(body);
    const timeout = setTimeout(() => reject(new Error(`Timeout`)), timeoutMs);

    const req = http.request({
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) },
    }, (res) => {
      clearTimeout(timeout);
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`JSON parse: ${e.message}`)); }
      });
    });

    req.on('error', (e) => { clearTimeout(timeout); reject(e); });
    req.write(postData);
    req.end();
  });
}

// ─── Circuit Breaker (Simple Implementation) ────────────────────────────────

const circuitBreakers = {};

function getBreaker(serviceName) {
  if (!circuitBreakers[serviceName]) {
    circuitBreakers[serviceName] = { failures: 0, state: 'CLOSED', openedAt: 0 };
  }
  return circuitBreakers[serviceName];
}

function recordFailure(serviceName) {
  const breaker = getBreaker(serviceName);
  breaker.failures++;
  if (breaker.failures >= config.failureThreshold) {
    breaker.state = 'OPEN';
    breaker.openedAt = Date.now();
    console.error(`[CIRCUIT BREAKER] ${serviceName} → OPEN after ${breaker.failures} failures`);
  }
}

function recordSuccess(serviceName) {
  const breaker = getBreaker(serviceName);
  breaker.failures = 0;
  breaker.state = 'CLOSED';
}

function isCircuitOpen(serviceName) {
  const breaker = getBreaker(serviceName);
  if (breaker.state === 'OPEN') {
    if (Date.now() - breaker.openedAt > config.recoveryTimeoutMs) {
      breaker.state = 'HALF-OPEN';
      return false; // Allow one test request
    }
    return true;
  }
  return false;
}

// ─── Agent Chain ────────────────────────────────────────────────────────────

async function processEntry(entry) {
  const logUuid = entry.log_uuid;
  console.log(`\n🛡 [AEGIS] 🔎 Incoming: ${logUuid} — ${entry.event_type}`);

  // === TRIAGE SKILL (pure computation) ===
  cognitiveRamWrite(`context_triage_${logUuid}`, entry);
  const triageResult = triageScore(entry);

  console.log(`🔍 [TRIAGE] Heuristic engine analyzing behavior...`);
  console.log(`   └─ Score: ${triageResult.score} (${triageResult.severity}) | Indicators: [${triageResult.heuristic_flags.join(', ')}]`);

  // === STORAGE SKILL (HTTP → Python correlation /ingest) ===
  // Ref: §3.1 — "Every ingested log... must be embedded and stored in the ChromaDB vector space"
  try {
    await httpPost(`${config.correlationServiceUrl}/ingest`, {
      synthetic_intent: entry.synthetic_intent,
      log_uuid: logUuid,
      event_timestamp: Date.now() / 1000,
      event_type: entry.event_type,
      source_ip: entry.source_ip,
      dest_ip: entry.dest_ip,
      hostname: entry.hostname,
    });
    console.log(`💾 [MEMORY] Encoding log into semantic vector space (ChromaDB)`);
    
    // === GRAPH INGESTION (HTTP → Python) ===
    // Ingest raw log into graph for real-time visualization
    try {
      await httpPost(`${config.graphServiceUrl}/graph/ingest/raw`, entry);
      console.log(`🕸️ [GRAPH] Projecting entities [${entry.hostname}, ${entry.process_name || 'N/A'}] onto Knowledge Graph`);
    } catch (e) {
      console.error(`[GRAPH] Ingestion failed: ${e.message}`);
    }
  } catch (e) {
    console.error(`[STORAGE] Ingestion failed: ${e.message}`);
    // Non-blocking: continue with triage even if storage fails
  }

  if (triageResult.severity === 'BENIGN') {
    console.log(`✅ [TRIAGE] Activity matches baseline — Ignoring.`);
    cognitiveRamDelete(`context_triage_${logUuid}`);
    return;
  }

  // Write triage output + manifest
  cognitiveRamWrite(`context_correlation_${logUuid}`, {
    entry, triage: triageResult,
  });
  cognitiveRamWrite(`context_manifest_${logUuid}`, {
    log_uuid: logUuid, from_skill: 'triage', schema_version: '1.0.0',
    timestamp: new Date().toISOString(),
  });

  // P0 immediate alert → Telegram
  if (triageResult.severity === 'P0') {
    console.log(`🚨 [ALERT] P0 CRITICAL — Triggering immediate tactical alert`);
    try {
      await httpPost(`${config.notificationServiceUrl}/notify/telegram/raw`, {
        message: `🔴 *P0 CRITICAL — Pre-Correlation Alert*\n\nEvent: \`${entry.event_type}\`\nHost: \`${entry.hostname || 'unknown'}\`\nSource: \`${entry.source_ip || 'N/A'}\` → \`${entry.dest_ip || 'N/A'}\`\nLog UUID: \`${logUuid}\`\n\n_Full analysis in progress..._`,
        parse_mode: 'Markdown',
      }, 5000);
      console.log(`📬 [TELEGRAM] Tactical alert delivered successfully`);
    } catch (e) {
      console.error(`[TELEGRAM] P0 alert failed: ${e.message}`);
    }
  }

  // === CORRELATION SKILL (HTTP → Python) ===
  if (!triageResult.correlation_required) {
    console.log(`🔗 [CORRELATION] Skipped (not required for ${triageResult.severity})`);
    cognitiveRamWrite(`context_timeline_${logUuid}`, {
      triggering_log: entry, correlation: { cold_start: true, cluster_size: 0 },
    });
  } else {
    if (isCircuitOpen('correlation')) {
      console.error(`[CIRCUIT BREAKER] Correlation service circuit OPEN — dead-letter`);
      return;
    }

    try {
      const corrResult = await httpPost(`${config.correlationServiceUrl}/correlate`, {
        synthetic_intent: entry.synthetic_intent,
        event_timestamp: Date.now() / 1000,
        log_uuid: logUuid,
        event_type: entry.event_type,
      }, 120000);

      recordSuccess('correlation');
      if (corrResult.cluster_size > 1) {
        console.log(`✅ [CORRELATION] Identified attack cluster of ${corrResult.cluster_size} related events.`);
        console.log(`   └─ Temporal Span: ${corrResult.temporal_span_minutes.toFixed(1)} mins`);
      } else {
        console.log(`⚠️ [CORRELATION] No historical links found (Cold Start). Monitoring for further activity...`);
      }

      cognitiveRamWrite(`context_timeline_${logUuid}`, {
        triggering_log: entry, correlation: corrResult,
      });
      cognitiveRamWrite(`context_manifest_${logUuid}`, {
        log_uuid: logUuid, from_skill: 'correlation', schema_version: '1.0.0',
        timestamp: new Date().toISOString(),
      });
    } catch (e) {
      recordFailure('correlation');
      console.error(`[CORRELATION] Failed: ${e.message}`);
      return;
    }
  }

  // === TIMELINE SKILL (HTTP → Python synthesizer) ===
  if (isCircuitOpen('synthesizer')) {
    console.error(`[CIRCUIT BREAKER] Synthesizer circuit OPEN — dead-letter`);
    return;
  }

  try {
    const timelineContext = cognitiveRamRead(`context_timeline_${logUuid}`);
    console.log(`🧠 [SYNTHESIS] Reconstructing attack narrative using Qwen 2.5 LLM...`);
    console.log(`   └─ Input: ${timelineContext.correlation.cluster_size} related events + forensic context`);
    const synthResult = await httpPost(`${config.synthesizerServiceUrl}/synthesize`, {
      triggering_log: timelineContext.triggering_log,
      correlated_cluster: (timelineContext.correlation.correlated_entries || []).map(e => ({
        synthetic_intent: e.synthetic_intent,
        cosine_similarity: e.cosine_similarity,
        event_timestamp: e.event_timestamp,
        event_type: e.event_type || '',
        mitre_technique_hint: e.mitre_technique_hint || null,
      })),
      cold_start: timelineContext.correlation.cold_start || false,
    }, 600000); // 10 minute timeout for LLM queue

    recordSuccess('synthesizer');

    if (synthResult.success) {
      console.log(`✅ [TIMELINE] Forensic report generated (Confidence: ${synthResult.report.confidence * 100}%)`);
      console.log(`   └─ Narrative: ${synthResult.report.narrative.substring(0, 100)}...`);
      console.log(`   └─ MITRE: ${(synthResult.report.mitre_techniques || []).join(', ')}`);

      // === PROTOCOL ADAPTER: Telegram delivery ===
      try {
        await httpPost(`${config.notificationServiceUrl}/notify/telegram`, {
          report: synthResult.report,
          severity: triageResult.severity,
        }, 10000);
        console.log(`[TELEGRAM] Report delivered for ${logUuid}`);
      } catch (e) {
        console.error(`[TELEGRAM] Delivery failed: ${e.message}`);
      }

      // === PROTOCOL ADAPTER: Knowledge Graph update ===
      try {
        await httpPost(`${config.graphServiceUrl}/graph/ingest`, {
          report: synthResult.report,
          severity: triageResult.severity,
        }, 5000);
        console.log(`[GRAPH] Report ingested for ${logUuid}`);
      } catch (e) {
        console.error(`[GRAPH] Ingestion failed: ${e.message}`);
      }
    } else {
      console.error(`[TIMELINE] ❌ Synthesis failed: ${synthResult.error}`);
    }
  } catch (e) {
    recordFailure('synthesizer');
    console.error(`[TIMELINE] Failed: ${e.message}`);
  }

  // Cleanup Cognitive RAM
  cognitiveRamDelete(`context_triage_${logUuid}`);
  cognitiveRamDelete(`context_correlation_${logUuid}`);
  cognitiveRamDelete(`context_timeline_${logUuid}`);
  cognitiveRamDelete(`context_manifest_${logUuid}`);
}

// ─── HEARTBEAT Loop ─────────────────────────────────────────────────────────

let running = false;

async function heartbeatTick() {
  try {
    const result = await httpGet(
      `${config.ingestionApiUrl}/queue/next`,
      config.httpTimeoutMs
    );

    if (result.found && result.entry) {
      await processEntry(result.entry);
    }
  } catch (e) {
    // Timeout or connection error — skip this tick
    if (!e.message.includes('Timeout')) {
      console.error(`[HEARTBEAT] Queue poll error: ${e.message}`);
    }
  }
}

async function startHeartbeat() {
  console.log('═══════════════════════════════════════════════════');
  console.log('  AEGIS OpenClaw Gateway v1.0.0');
  console.log('  Autonomous SOC Forensic Analyst');
  console.log('═══════════════════════════════════════════════════');
  console.log(`  Poll interval: ${config.pollIntervalMs}ms`);
  console.log(`  HTTP timeout: ${config.httpTimeoutMs}ms`);
  console.log(`  Ingestion API: ${config.ingestionApiUrl}`);
  console.log(`  Correlation: ${config.correlationServiceUrl}`);
  console.log(`  Synthesizer: ${config.synthesizerServiceUrl}`);
  console.log('═══════════════════════════════════════════════════\n');

  loadThreatLists();
  running = true;

  while (running) {
    await heartbeatTick();
    await new Promise(resolve => setTimeout(resolve, config.pollIntervalMs));
  }
}

// ─── Entry Point ────────────────────────────────────────────────────────────

startHeartbeat().catch(e => {
  console.error(`[AEGIS] Fatal error: ${e.message}`);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[AEGIS] Shutting down...');
  running = false;
  setTimeout(() => process.exit(0), 1000);
});

module.exports = { triageScore, config, processEntry };
