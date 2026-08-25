import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

import { VddStatusPoller } from '../../src_assets/common/assets/web/vdd_status_poller.js';

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  return `http://127.0.0.1:${address.port}/api/vdd/status`;
}

async function close(server) {
  if (!server.listening) return;
  server.close();
  await once(server, 'close');
}

function fetchStatus(url) {
  return async (signal) => {
    const response = await fetch(url, { signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  };
}

test('rejects incomplete callbacks and keeps a stopped poller dormant', async () => {
  const callback = () => {};
  assert.throws(() => new VddStatusPoller({}), /requires load/);
  assert.throws(
    () => new VddStatusPoller({ load: callback, onError: callback }),
    /requires load/,
  );
  assert.throws(
    () => new VddStatusPoller({ load: callback, onStatus: callback }),
    /requires load/,
  );
  assert.throws(
    () => new VddStatusPoller({
      load: callback,
      onStatus: callback,
      onError: callback,
      intervalMs: Number.NaN,
    }),
    /must be positive/,
  );
  assert.throws(
    () => new VddStatusPoller({
      load: callback,
      onStatus: callback,
      onError: callback,
      intervalMs: 0,
    }),
    /must be positive/,
  );

  const dormant = new VddStatusPoller({
    load: callback,
    onStatus: callback,
    onError: callback,
  });
  dormant.setVisible(true);
  await dormant.poll();
  dormant.stop();
});

test('polls Ready, Streaming, Ready without overlapping real HTTP requests', async () => {
  const payloads = [
    { active: false, deliveryPolicy: null },
    { active: true, deliveryPolicy: 'latency' },
    { active: false, deliveryPolicy: null },
  ];
  let requestIndex = 0;
  let activeRequests = 0;
  let maximumActiveRequests = 0;
  const server = createServer(async (_request, response) => {
    activeRequests += 1;
    maximumActiveRequests = Math.max(maximumActiveRequests, activeRequests);
    await delay(15);
    const payload = payloads[Math.min(requestIndex, payloads.length - 1)];
    requestIndex += 1;
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(payload));
    activeRequests -= 1;
  });
  const url = await listen(server);
  const updates = [];
  let poller;
  try {
    await Promise.race([
      new Promise((resolve, reject) => {
        poller = new VddStatusPoller({
          load: fetchStatus(url),
          intervalMs: 1,
          onStatus(status) {
            updates.push(status);
            if (updates.length === payloads.length) {
              poller.stop();
              resolve();
            }
          },
          onError: reject,
        });
        poller.start(true);
      }),
      delay(1000).then(() => {
        throw new Error('Timed out waiting for VDD status transitions');
      }),
    ]);
    assert.deepEqual(updates, payloads);
    assert.equal(maximumActiveRequests, 1);
  } finally {
    poller?.stop();
    await close(server);
  }
});

test('retains the last valid status when the next real HTTP request fails', async () => {
  const ready = { active: false, deliveryPolicy: null };
  let requestIndex = 0;
  const server = createServer((_request, response) => {
    if (requestIndex++ === 0) {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(ready));
      return;
    }
    response.writeHead(503);
    response.end();
  });
  const url = await listen(server);
  let poller;
  try {
    const retained = await Promise.race([
      new Promise((resolve) => {
        poller = new VddStatusPoller({
          load: fetchStatus(url),
          intervalMs: 1,
          onStatus() {},
          onError(_error, lastStatus) {
            poller.stop();
            resolve(lastStatus);
          },
        });
        poller.start(true);
      }),
      delay(1000).then(() => {
        throw new Error('Timed out waiting for transient VDD status failure');
      }),
    ]);
    assert.deepEqual(retained, ready);
  } finally {
    poller?.stop();
    await close(server);
  }
});

test('stop aborts an in-flight request without publishing an error or update', async () => {
  const server = createServer(async (_request, response) => {
    await delay(100);
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ active: true, deliveryPolicy: 'quality' }));
  });
  const url = await listen(server);
  const updates = [];
  const errors = [];
  const poller = new VddStatusPoller({
    load: fetchStatus(url),
    intervalMs: 1,
    onStatus: (status) => updates.push(status),
    onError: (error) => errors.push(error),
  });
  try {
    poller.start(true);
    await delay(10);
    poller.stop();
    await delay(130);
    assert.deepEqual(updates, []);
    assert.deepEqual(errors, []);
  } finally {
    poller.stop();
    await close(server);
  }
});

test('visibility pauses scheduled work and resumes with one immediate request', async () => {
  let requests = 0;
  const server = createServer((_request, response) => {
    requests += 1;
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ active: false, deliveryPolicy: null }));
  });
  const url = await listen(server);
  let resolveUpdate;
  let update = new Promise((resolve) => {
    resolveUpdate = resolve;
  });
  const poller = new VddStatusPoller({
    load: fetchStatus(url),
    intervalMs: 1000,
    onStatus: () => resolveUpdate(),
    onError: (error) => {
      throw error;
    },
  });
  try {
    poller.start(false);
    poller.start(false);
    await poller.poll();
    poller.setVisible(false);
    assert.equal(requests, 0);

    poller.setVisible(true);
    poller.setVisible(true);
    void poller.poll();
    await update;
    await delay(5);
    assert.equal(requests, 1);

    poller.setVisible(false);
    await delay(5);
    assert.equal(requests, 1);

    update = new Promise((resolve) => {
      resolveUpdate = resolve;
    });
    poller.setVisible(true);
    await update;
    assert.equal(requests, 2);
  } finally {
    poller.stop();
    await close(server);
  }
});

test('hiding after a completed response discards that now-invisible update', async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ active: true, deliveryPolicy: 'latency' }));
  });
  const url = await listen(server);
  const updates = [];
  const errors = [];
  let poller;
  poller = new VddStatusPoller({
    async load(signal) {
      const status = await fetchStatus(url)(signal);
      poller.setVisible(false);
      return status;
    },
    intervalMs: 1,
    onStatus: (status) => updates.push(status),
    onError: (error) => errors.push(error),
  });
  try {
    poller.start(true);
    await delay(30);
    assert.deepEqual(updates, []);
    assert.deepEqual(errors, []);
  } finally {
    poller.stop();
    await close(server);
  }
});
