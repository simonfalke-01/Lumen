export const VDD_STATUS_POLL_INTERVAL_MS = 2000;

/**
 * Poll one read-only status endpoint without overlap and only while visible.
 */
export class VddStatusPoller {
  constructor({ load, onStatus, onError, intervalMs = VDD_STATUS_POLL_INTERVAL_MS }) {
    if (typeof load !== 'function' || typeof onStatus !== 'function' || typeof onError !== 'function') {
      throw new TypeError('VDD status poller requires load, onStatus, and onError callbacks');
    }
    if (!Number.isFinite(intervalMs) || intervalMs < 1) {
      throw new RangeError('VDD status poll interval must be positive');
    }
    this.load = load;
    this.onStatus = onStatus;
    this.onError = onError;
    this.intervalMs = intervalMs;
    this.running = false;
    this.visible = false;
    this.inFlight = false;
    this.timer = null;
    this.abortController = null;
    this.lastStatus = null;
  }

  start(visible = true) {
    if (this.running) return;
    this.running = true;
    this.visible = Boolean(visible);
    if (this.visible) void this.poll();
  }

  setVisible(visible) {
    const nextVisible = Boolean(visible);
    if (this.visible === nextVisible) return;
    this.visible = nextVisible;
    this.clearTimer();
    if (!this.visible) {
      this.abortController?.abort();
      return;
    }
    if (this.running && !this.inFlight) void this.poll();
  }

  stop() {
    this.running = false;
    this.visible = false;
    this.clearTimer();
    this.abortController?.abort();
  }

  clearTimer() {
    clearTimeout(this.timer);
    this.timer = null;
  }

  schedule() {
    this.clearTimer();
    if (!this.running || !this.visible) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.poll();
    }, this.intervalMs);
  }

  async poll() {
    if (!this.running || !this.visible || this.inFlight) return;
    this.inFlight = true;
    const controller = new AbortController();
    this.abortController = controller;
    try {
      const status = await this.load(controller.signal);
      if (!this.running || !this.visible || controller.signal.aborted) return;
      this.lastStatus = status;
      this.onStatus(status);
    } catch (error) {
      if (this.running && this.visible && !controller.signal.aborted) {
        this.onError(error, this.lastStatus);
      }
    } finally {
      this.abortController = null;
      this.inFlight = false;
      this.schedule();
    }
  }
}
