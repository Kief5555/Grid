import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const root = await mkdtemp(path.join(os.tmpdir(), 'grid-test-'));
const port = 36000 + Math.floor(Math.random() * 2000);
const baseUrl = `http://127.0.0.1:${port}`;
let server;
let serverOutput = '';

const request = async (pathname, { method = 'GET', token, headers = {}, body } = {}) => {
    const requestHeaders = new Headers(headers);
    if (token) {
        requestHeaders.set('Authorization', `Bearer ${token}`);
    }

    const response = await fetch(`${baseUrl}${pathname}`, { method, headers: requestHeaders, body });
    const contentType = response.headers.get('content-type') || '';
    const data = contentType.includes('application/json') ? await response.json() : await response.arrayBuffer();
    return { response, data };
};

const waitForServer = async () => {
    let lastError;
    for (let attempt = 0; attempt < 50; attempt++) {
        try {
            const response = await fetch(`${baseUrl}/health`);
            if (response.ok) {
                return;
            }
        } catch (error) {
            lastError = error;
        }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error(`Server did not start: ${lastError?.message || serverOutput}`);
};

test.before(async () => {
    server = spawn(process.execPath, ['index.js'], {
        cwd: process.cwd(),
        env: {
            ...process.env,
            PORT: String(port),
            JWT: 'test-jwt-secret',
            RKEY: 'test-registration-secret',
            FILTER_MIME: 'true',
            DATA_DIR: path.join(root, 'data'),
            FILES_DIR: path.join(root, 'files'),
            TEMP_DIR: path.join(root, 'temp')
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    server.stdout.on('data', chunk => {
        serverOutput += chunk;
    });
    server.stderr.on('data', chunk => {
        serverOutput += chunk;
    });
    await waitForServer();
});

test.after(async () => {
    server?.kill();
    await rm(root, { recursive: true, force: true });
});

test('finalizes resumable APK uploads and protects private downloads', async () => {
    for (const username of ['owner', 'other']) {
        const { response } = await request('/api/user/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                password: 'correct-horse-battery',
                registerKey: 'test-registration-secret'
            })
        });
        assert.equal(response.status, 201);
    }

    const login = async username => {
        const { response, data } = await request('/api/user/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password: 'correct-horse-battery' })
        });
        assert.equal(response.status, 200);
        return data.data.token;
    };
    const ownerToken = await login('owner');
    const otherToken = await login('other');

    const publicStatus = await request('/status');
    assert.equal(publicStatus.response.status, 200);
    const permissivePreflight = await request('/status', {
        method: 'OPTIONS',
        headers: {
            Origin: 'https://untrusted.example',
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'authorization, username, password, cvpn'
        }
    });
    assert.equal(permissivePreflight.response.status, 204);
    assert.equal(permissivePreflight.response.headers.get('access-control-allow-origin'), 'https://untrusted.example');
    assert.equal(permissivePreflight.response.headers.get('access-control-allow-credentials'), 'true');
    assert.match(permissivePreflight.response.headers.get('access-control-allow-headers'), /password/);

    const totalSize = (1024 * 1024) + 1;
    const { response: initResponse, data: init } = await request('/api/file/upload/init', {
        method: 'POST',
        token: ownerToken,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            filename: 'release.apk',
            size: totalSize,
            chunkSize: 1024 * 1024,
            private: true,
            accessKey: true
        })
    });
    assert.equal(initResponse.status, 201);
    const { sessionID } = init.data;

    const incomplete = await request(`/api/file/upload/complete/${sessionID}`, {
        method: 'POST',
        token: ownerToken
    });
    assert.equal(incomplete.response.status, 409);
    assert.deepEqual(incomplete.data.data.missingChunkIndexes, [0, 1]);

    const apk = new Uint8Array(totalSize);
    apk[0] = 1;
    apk[totalSize - 1] = 2;
    for (let index = 0; index < 2; index++) {
        const start = index * 1024 * 1024;
        const form = new FormData();
        form.append('chunk', new Blob([apk.slice(start, Math.min(start + (1024 * 1024), totalSize))]), 'chunk.bin');
        const { response, data } = await request(`/api/file/upload/chunk/${sessionID}`, {
            method: 'POST',
            token: ownerToken,
            headers: {
                'X-Chunk-Index': String(index),
                'X-Total-Chunks': '2'
            },
            body: form
        });
        assert.equal(response.status, 200);
        assert.equal(data.data.readyToComplete, index === 1);
    }

    const completed = await request(`/api/file/upload/complete/${sessionID}`, {
        method: 'POST',
        token: ownerToken
    });
    assert.equal(completed.response.status, 201);
    assert.match(completed.data.data.sha256, /^[a-f0-9]{64}$/);
    const { fileID, privateKey } = completed.data.data;

    const sessionStatus = await request(`/api/file/upload/session/${sessionID}`, { token: ownerToken });
    assert.equal(sessionStatus.response.status, 200);
    assert.equal(sessionStatus.data.data.completed, true);
    assert.equal(sessionStatus.data.data.result.fileID, fileID);

    const retry = await request(`/api/file/upload/complete/${sessionID}`, {
        method: 'POST',
        token: ownerToken
    });
    assert.equal(retry.response.status, 200);
    assert.equal(retry.data.data.fileID, fileID);

    const unauthenticated = await request(`/download/${fileID}?key=${privateKey}`);
    assert.equal(unauthenticated.response.status, 401);
    const wrongOwner = await request(`/download/${fileID}?key=${privateKey}`, { token: otherToken });
    assert.equal(wrongOwner.response.status, 401);

    const download = await request(`/download/${fileID}?key=${privateKey}`, { token: ownerToken });
    assert.equal(download.response.status, 200);
    assert.equal(download.response.headers.get('content-type'), 'application/vnd.android.package-archive');
    assert.equal(download.response.headers.get('accept-ranges'), 'bytes');
    assert.equal(download.response.headers.get('content-length'), String(totalSize));
    assert.equal(download.response.headers.get('etag'), `"${completed.data.data.sha256}"`);
    assert.match(download.response.headers.get('cache-control'), /no-transform/);
    assert.equal(download.data.byteLength, totalSize);

    const head = await request(`/download/${fileID}?key=${privateKey}`, {
        method: 'HEAD',
        token: ownerToken
    });
    assert.equal(head.response.status, 200);
    assert.equal(head.response.headers.get('content-length'), String(totalSize));
    assert.equal(head.response.headers.get('etag'), download.response.headers.get('etag'));
    assert.equal(head.data.byteLength, 0);

    // This matches Android DownloadManager's resume request: it keeps the ETag
    // from the initial response and sends it in If-Match with an open range.
    const resumedDownload = await request(`/download/${fileID}?key=${privateKey}`, {
        token: ownerToken,
        headers: {
            Range: 'bytes=1-',
            'If-Match': download.response.headers.get('etag')
        }
    });
    assert.equal(resumedDownload.response.status, 206);
    assert.equal(resumedDownload.response.headers.get('content-range'), `bytes 1-${totalSize - 1}/${totalSize}`);
    assert.equal(resumedDownload.response.headers.get('content-length'), String(totalSize - 1));
    assert.equal(resumedDownload.response.headers.get('etag'), download.response.headers.get('etag'));
    assert.equal(resumedDownload.data.byteLength, totalSize - 1);

    const staleResume = await request(`/download/${fileID}?key=${privateKey}`, {
        token: ownerToken,
        headers: {
            Range: 'bytes=1-',
            'If-Match': '"stale-checksum"'
        }
    });
    assert.equal(staleResume.response.status, 412);
});
