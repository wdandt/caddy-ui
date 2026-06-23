import { Hono } from 'hono';
import fs from 'fs';
import readline from 'readline';
import path from 'path';
import { readDb } from '../db.js';
import { JWT_SECRET } from '../utils/crypto.js';

export const logsRoutes = new Hono();

// We map caddy_logs volume to /app/logs in docker-compose.yml for caddy-ui
const LOG_FILE_PATH = '/app/logs/access.log';

logsRoutes.get('/api/logs', async (c) => {
    const linesToRead = parseInt(c.req.query('lines')) || 100;
    const instanceId = c.req.query('instanceId');
    const db = readDb();

    let instance = null;
    if (instanceId) {
        instance = db.instances.find(i => i.id === instanceId);
        if (!instance) {
            return c.json({ error: 'Instance not found' }, 404);
        }
    } else {
        instance = db.instances.find(i => i.isLocal) || db.instances[0];
    }

    if (!instance || instance.isLocal) {
        if (!fs.existsSync(LOG_FILE_PATH)) {
            return c.json({ error: 'Log file not found. Caddy might not have generated any logs yet, or the volume is not mounted correctly.' }, 404);
        }

        try {
            const stats = fs.statSync(LOG_FILE_PATH);
            const fileSize = stats.size;
            
            const chunkSize = 1024 * 1024; // 1MB
            const start = Math.max(0, fileSize - chunkSize);
            
            const stream = fs.createReadStream(LOG_FILE_PATH, { start, end: fileSize });
            const rl = readline.createInterface({
                input: stream,
                crlfDelay: Infinity
            });

            const lines = [];
            for await (const line of rl) {
                if (line.trim()) {
                    try {
                        lines.push(JSON.parse(line));
                    } catch (e) {
                        lines.push({ raw: line });
                    }
                }
            }
            
            const lastLines = lines.slice(-linesToRead).reverse();
            return c.json(lastLines);
        } catch (err) {
            console.error('Error reading local logs:', err);
            return c.json({ error: 'Failed to read logs' }, 500);
        }
    } else {
        // Fetch logs from remote instance
        try {
            const url = new URL(instance.url);
            const targetHost = url.hostname;
            const logUrl = `http://${targetHost}:80/_caddyui/logs/access.log`;

            const response = await fetch(logUrl, {
                headers: {
                    'Authorization': `Bearer ${JWT_SECRET}`,
                    'Range': 'bytes=-1048576'
                },
                signal: AbortSignal.timeout(5000)
            });

            if (!response.ok) {
                if (response.status === 404) {
                    return c.json({ error: 'Remote log file not found. Ensure the config is synced.' }, 404);
                }
                return c.json({ error: `Failed to fetch remote logs: ${response.status} ${response.statusText}` }, 500);
            }

            const text = await response.text();
            const lines = text.split('\n').map(l => l.trim()).filter(l => l);
            if (response.status === 206 && lines.length > 1) {
                // If it's partial content, the first line might be cut off
                lines.shift();
            }

            const parsedLines = lines.map(line => {
                try {
                    return JSON.parse(line);
                } catch (e) {
                    return { raw: line };
                }
            });

            const lastLines = parsedLines.slice(-linesToRead).reverse();
            return c.json(lastLines);

        } catch (err) {
            console.error('Error reading remote logs:', err);
            return c.json({ error: `Failed to read remote logs: ${err.message}` }, 500);
        }
    }
});
