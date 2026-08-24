<script setup>
import { computed, ref } from 'vue'
import {
  Info,
  TriangleAlert,
} from '@lucide/vue'
import Checkbox from "../../Checkbox.vue";

const props = defineProps([
  'platform',
  'config'
])

const defaultMoonlightPort = 47989

const config = ref(props.config)
const effectivePort = computed(() => +config.value?.port ?? defaultMoonlightPort)
const protocolV3Permissions = computed(() => Number(config.value?.protocol_v3_pairing_permissions ?? 0x17) | 0x17)
const protocolV3PermissionEnabled = bit => (protocolV3Permissions.value & (1 << bit)) !== 0
const toggleProtocolV3Permission = bit => {
  config.value.protocol_v3_pairing_permissions = protocolV3Permissions.value ^ (1 << bit)
}
</script>

<template>
  <div id="network" class="config-page">
    <!-- UPnP -->
    <Checkbox class="mb-3"
              id="upnp"
              locale-prefix="config"
              v-model="config.upnp"
              default="false"
    ></Checkbox>

    <!-- Address family -->
    <div class="mb-3">
      <label for="address_family" class="form-label">{{ $t('config.address_family') }}</label>
      <select id="address_family" class="form-select" v-model="config.address_family">
        <option value="ipv4">{{ $t('config.address_family_ipv4') }}</option>
        <option value="both">{{ $t('config.address_family_both') }}</option>
      </select>
      <div class="form-text">{{ $t('config.address_family_desc') }}</div>
    </div>

    <!-- Bind address -->
    <div class="mb-3">
      <label for="bind_address" class="form-label">{{ $t('config.bind_address') }}</label>
      <input type="text" class="form-control" id="bind_address" v-model="config.bind_address" />
      <div class="form-text">{{ $t('config.bind_address_desc') }}</div>
    </div>

    <!-- Port family -->
    <div class="mb-3">
      <label for="port" class="form-label">{{ $t('config.port') }}</label>
      <input type="number" min="1029" max="65514" class="form-control" id="port" :placeholder="defaultMoonlightPort"
             v-model="config.port" />
      <div class="form-text">{{ $t('config.port_desc') }}</div>
      <!-- Add warning if any port is less than 1024 -->
      <div class="alert alert-danger" v-if="(+effectivePort - 5) < 1024">
        <TriangleAlert :size="20" /> {{ $t('config.port_alert_1') }}
      </div>
      <!-- Add warning if any port is above 65535 -->
      <div class="alert alert-danger" v-if="(+effectivePort + 21) > 65535">
        <TriangleAlert :size="20" /> {{ $t('config.port_alert_2') }}
      </div>
      <!-- Create a port table for the various ports needed by Sunshine -->
      <table class="table">
        <thead>
        <tr>
          <th scope="col">{{ $t('config.port_protocol') }}</th>
          <th scope="col">{{ $t('config.port_port') }}</th>
          <th scope="col">{{ $t('config.port_note') }}</th>
        </tr>
        </thead>
        <tbody>
        <tr>
          <!-- HTTPS -->
          <td>{{ $t('config.port_tcp') }}</td>
          <td>{{+effectivePort - 5}}</td>
          <td></td>
        </tr>
        <tr>
          <!-- HTTP -->
          <td>{{ $t('config.port_tcp') }}</td>
          <td>{{+effectivePort}}</td>
          <td>
            <div class="alert alert-primary" role="alert" v-if="+effectivePort !== defaultMoonlightPort">
              <Info :size="20" /> {{ $t('config.port_http_port_note') }}
            </div>
          </td>
        </tr>
        <tr>
          <!-- Web UI -->
          <td>{{ $t('config.port_tcp') }}</td>
          <td>{{+effectivePort + 1}}</td>
          <td>{{ $t('config.port_web_ui') }}</td>
        </tr>
        <tr>
          <!-- RTSP -->
          <td>{{ $t('config.port_tcp') }}</td>
          <td>{{+effectivePort + 21}}</td>
          <td></td>
        </tr>
        <tr>
          <!-- Video, Control, Audio -->
          <td>{{ $t('config.port_udp') }}</td>
          <td>{{+effectivePort + 9}} - {{+effectivePort + 11}}</td>
          <td></td>
        </tr>
        <!--            <tr>-->
        <!--              &lt;!&ndash; Mic &ndash;&gt;-->
        <!--              <td>UDP</td>-->
        <!--              <td>{{+effectivePort + 13}}</td>-->
        <!--              <td></td>-->
        <!--            </tr>-->
        </tbody>
      </table>
      <!-- add warning about exposing web ui to the internet -->
      <div class="alert alert-warning" v-if="config.origin_web_ui_allowed === 'wan'">
        <TriangleAlert :size="20" /> {{ $t('config.port_warning') }}
      </div>
    </div>

    <!-- Origin Web UI Allowed -->
    <div class="mb-3">
      <label for="origin_web_ui_allowed" class="form-label">{{ $t('config.origin_web_ui_allowed') }}</label>
      <select id="origin_web_ui_allowed" class="form-select" v-model="config.origin_web_ui_allowed">
        <option value="pc">{{ $t('config.origin_web_ui_allowed_pc') }}</option>
        <option value="lan">{{ $t('config.origin_web_ui_allowed_lan') }}</option>
        <option value="wan">{{ $t('config.origin_web_ui_allowed_wan') }}</option>
      </select>
      <div class="form-text">{{ $t('config.origin_web_ui_allowed_desc') }}</div>
    </div>

    <!-- CSRF Allowed Origins -->
    <div class="mb-3">
      <label for="csrf_allowed_origins" class="form-label">{{ $t('config.csrf_allowed_origins') }}</label>
      <input type="text"
             class="form-control"
             id="csrf_allowed_origins"
             v-model="config.csrf_allowed_origins" />
      <div class="form-text">{{ $t('config.csrf_allowed_origins_desc') }}</div>
    </div>

    <!-- External IP -->
    <div class="mb-3">
      <label for="external_ip" class="form-label">{{ $t('config.external_ip') }}</label>
      <input type="text" class="form-control" id="external_ip" placeholder="123.456.789.12" v-model="config.external_ip" />
      <div class="form-text">{{ $t('config.external_ip_desc') }}</div>
    </div>

    <!-- LAN Encryption Mode -->
    <div class="mb-3">
      <label for="lan_encryption_mode" class="form-label">{{ $t('config.lan_encryption_mode') }}</label>
      <select id="lan_encryption_mode" class="form-select" v-model="config.lan_encryption_mode">
        <option value="0">{{ $t('_common.disabled_def') }}</option>
        <option value="1">{{ $t('config.lan_encryption_mode_1') }}</option>
        <option value="2">{{ $t('config.lan_encryption_mode_2') }}</option>
      </select>
      <div class="form-text">{{ $t('config.lan_encryption_mode_desc') }}</div>
    </div>

    <!-- WAN Encryption Mode -->
    <div class="mb-3">
      <label for="wan_encryption_mode" class="form-label">{{ $t('config.wan_encryption_mode') }}</label>
      <select id="wan_encryption_mode" class="form-select" v-model="config.wan_encryption_mode">
        <option value="0">{{ $t('_common.disabled') }}</option>
        <option value="1">{{ $t('config.wan_encryption_mode_1') }}</option>
        <option value="2">{{ $t('config.wan_encryption_mode_2') }}</option>
      </select>
      <div class="form-text">{{ $t('config.wan_encryption_mode_desc') }}</div>
    </div>

    <!-- Ping Timeout -->
    <div class="mb-3">
      <label for="ping_timeout" class="form-label">{{ $t('config.ping_timeout') }}</label>
      <input type="text" class="form-control" id="ping_timeout" placeholder="10000" v-model="config.ping_timeout" />
      <div class="form-text">{{ $t('config.ping_timeout_desc') }}</div>
    </div>

    <!-- Packet Size Limit -->
    <div class="mb-3">
      <label for="packetsize" class="form-label">{{ $t('config.packetsize') }}</label>
      <input type="number" min="0" max="65535" class="form-control" id="packetsize" placeholder="0" v-model="config.packetsize" />
      <div class="form-text">{{ $t('config.packetsize_desc') }}</div>
    </div>

    <hr class="my-4" />
    <h3 class="h5">{{ $t('config.protocol_v3') }}</h3>
    <p class="text-body-secondary">{{ $t('config.protocol_v3_desc') }}</p>

    <Checkbox class="mb-3"
              id="protocol_v3_enabled"
              locale-prefix="config"
              v-model="config.protocol_v3_enabled"
              default="true"
    ></Checkbox>

    <Checkbox class="mb-3"
              id="legacy_compatibility"
              locale-prefix="config"
              v-model="config.legacy_compatibility"
              default="true"
    ></Checkbox>

    <div class="row g-3 mb-3">
      <div class="col-12 col-md-6">
        <label for="protocol_v3_port" class="form-label">{{ $t('config.protocol_v3_port') }}</label>
        <input id="protocol_v3_port" v-model="config.protocol_v3_port" class="form-control"
               type="number" min="1024" max="65535" placeholder="48030" />
        <div class="form-text">{{ $t('config.protocol_v3_port_desc') }}</div>
      </div>
      <div class="col-12 col-md-6">
        <label for="protocol_v3_profile" class="form-label">{{ $t('config.protocol_v3_profile') }}</label>
        <select id="protocol_v3_profile" v-model="config.protocol_v3_profile" class="form-select">
          <option value="latency">{{ $t('config.protocol_v3_profile_latency') }}</option>
          <option value="quality">{{ $t('config.protocol_v3_profile_quality') }}</option>
        </select>
        <div class="form-text">{{ $t('config.protocol_v3_profile_desc') }}</div>
      </div>
    </div>

    <fieldset class="mb-3">
      <legend class="h6">{{ $t('config.protocol_v3_optional_permissions') }}</legend>
      <div class="form-check">
        <input id="protocol_v3_permission_microphone" class="form-check-input" type="checkbox"
               :checked="protocolV3PermissionEnabled(3)" @change="toggleProtocolV3Permission(3)" />
        <label for="protocol_v3_permission_microphone" class="form-check-label">
          {{ $t('config.protocol_v3_permission_microphone') }}
        </label>
      </div>
      <div class="form-check mt-2">
        <input id="protocol_v3_permission_quit" class="form-check-input" type="checkbox"
               :checked="protocolV3PermissionEnabled(5)" @change="toggleProtocolV3Permission(5)" />
        <label for="protocol_v3_permission_quit" class="form-check-label">
          {{ $t('config.protocol_v3_permission_quit') }}
        </label>
      </div>
      <div class="form-text">{{ $t('config.protocol_v3_optional_permissions_desc') }}</div>
    </fieldset>

  </div>
</template>

<style scoped>

</style>
