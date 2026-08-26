<template>
  <section class="vdd-status my-4" aria-labelledby="vdd-status-title">
    <header class="vdd-status__header">
      <h2 id="vdd-status-title" class="vdd-status__title">{{ $t('index.vdd_title') }}</h2>
      <p
        class="vdd-status__state"
        :class="`vdd-status__state--${statusTone}`"
        aria-live="polite"
      >
        {{ stateLabel }}
      </p>
    </header>

    <p v-if="loading" class="vdd-status__message">
      {{ $t('index.vdd_checking') }}
    </p>
    <p v-else-if="failed || !status" class="vdd-status__message vdd-status__message--error">
      {{ $t('index.vdd_unavailable') }}
    </p>
    <template v-else>
      <dl class="vdd-status__details">
        <div class="vdd-status__detail">
          <dt>{{ $t('index.vdd_driver') }}</dt>
          <dd>{{ driverLabel }}</dd>
        </div>
        <div class="vdd-status__detail">
          <dt>{{ $t('index.vdd_display') }}</dt>
          <dd>{{ modeLabel }}</dd>
        </div>
        <div class="vdd-status__detail">
          <dt>{{ $t('index.vdd_capture') }}</dt>
          <dd>{{ captureLabel }}</dd>
        </div>
      </dl>
      <p v-if="showDiagnostic" class="vdd-status__message vdd-status__message--warning">
        {{ diagnosticText }}
      </p>
    </template>
  </section>
</template>

<script>
import { VddStatusPoller } from './vdd_status_poller.js';

export default {
  name: 'VddStatus',
  data() {
    return {
      status: null,
      loading: true,
      failed: false,
      stale: false,
      poller: null,
    };
  },
  mounted() {
    this.poller = new VddStatusPoller({
      load: (signal) => this.loadStatus(signal),
      onStatus: (status) => this.applyStatus(status),
      onError: (_error, lastStatus) => this.applyError(lastStatus),
    });
    document.addEventListener('visibilitychange', this.handleVisibilityChange);
    this.poller.start(document.visibilityState === 'visible');
  },
  beforeUnmount() {
    document.removeEventListener('visibilitychange', this.handleVisibilityChange);
    this.poller?.stop();
    this.poller = null;
  },
  computed: {
    statusTone() {
      if (this.loading) return 'muted';
      if (this.failed || !this.status || !this.status.installed || !this.status.compatible || !this.status.deviceHealthy) {
        return 'error';
      }
      if (this.stale || this.status.quarantined || this.status.fallback || this.captureUnavailable) return 'warning';
      return 'ok';
    },
    stateLabel() {
      if (this.loading) return this.$t('index.vdd_checking_state');
      if (this.failed || !this.status) return this.$t('index.vdd_unavailable_state');
      if (!this.status.installed) return this.$t('index.vdd_not_installed');
      if (!this.status.compatible) return this.$t('index.vdd_update_required');
      if (!this.status.deviceHealthy) return this.$t('index.vdd_driver_issue');
      if (this.stale) return this.$t('index.vdd_update_delayed');
      if (this.status.quarantined) return this.$t('index.vdd_restart_required');
      if (this.captureUnavailable) return this.$t('index.vdd_unavailable_state');
      if (this.status.active) {
        return this.$t('index.vdd_streaming_policy', { policy: this.deliveryPolicyLabel });
      }
      return this.$t('index.vdd_ready');
    },
    driverLabel() {
      if (!this.status.installed) return this.$t('index.vdd_not_installed');
      if (!this.status.compatible) return this.$t('index.vdd_incompatible');
      if (!this.status.deviceHealthy && this.status.problem !== null) {
        return this.$t('index.vdd_windows_problem', { problem: this.status.problem });
      }
      if (!this.status.deviceHealthy) return this.$t('index.vdd_not_started');
      return this.$t('index.vdd_healthy');
    },
    modeLabel() {
      const mode = this.status.mode;
      if (!this.status.active || !mode) return this.$t('index.vdd_inactive');
      const range = mode.hdr ? this.$t('index.vdd_hdr') : this.$t('index.vdd_sdr');
      return this.$t('index.vdd_mode', {
        width: mode.width,
        height: mode.height,
        numerator: mode.refreshNumerator,
        denominator: mode.refreshDenominator,
        range,
        bitDepth: mode.bitDepth,
        generation: this.status.generation,
      });
    },
    captureLabel() {
      if (!this.status.active) return this.$t('index.vdd_inactive');
      if (this.status.quarantined) return this.$t('index.vdd_capture_stopped');
      if (this.status.directFrameBound) return this.$t('index.vdd_direct_frames');
      if (this.status.fallback) return this.$t('index.vdd_desktop_capture');
      return this.$t('index.vdd_unavailable_state');
    },
    deliveryPolicyLabel() {
      if (this.status?.deliveryPolicy === 'latency') return this.$t('index.vdd_policy_latency');
      if (this.status?.deliveryPolicy === 'quality') return this.$t('index.vdd_policy_quality');
      return this.$t('index.vdd_unavailable_state');
    },
    captureUnavailable() {
      return this.status?.captureState === 'unavailable';
    },
    showDiagnostic() {
      return this.stale || this.status.quarantined || this.status.fallback || this.captureUnavailable;
    },
    diagnosticText() {
      return this.stale ? this.$t('index.vdd_showing_last_status') : this.status.diagnostic;
    },
  },
  methods: {
    async loadStatus(signal) {
      const response = await fetch('./api/vdd/status', {
        cache: 'no-store',
        signal,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    },
    applyStatus(status) {
      this.status = status;
      this.loading = false;
      this.failed = false;
      this.stale = false;
    },
    applyError(lastStatus) {
      this.loading = false;
      if (lastStatus) {
        this.status = lastStatus;
        this.failed = false;
        this.stale = true;
      } else {
        this.failed = true;
      }
    },
    handleVisibilityChange() {
      this.poller?.setVisible(document.visibilityState === 'visible');
    },
  },
};
</script>
