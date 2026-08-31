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
const lspKnownPermissionMask = 0x7f
const lspDefaultPermissionMask = 0x57

const config = ref(props.config)
const effectivePort = computed(() => +config.value?.port ?? defaultMoonlightPort)
const lspPairingPermissions = computed(() => {
  const parsed = Number(config.value?.lsp_pairing_permissions)
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= lspKnownPermissionMask
    ? parsed
    : lspDefaultPermissionMask
})
const lspPermissionModel = bit => computed({
  get: () => (lspPairingPermissions.value & bit) !== 0,
  set: enabled => {
    config.value.lsp_pairing_permissions = enabled
      ? lspPairingPermissions.value | bit
      : lspPairingPermissions.value & ~bit
  },
})
const lspPermissionBrowse = lspPermissionModel(1 << 0)
const lspPermissionStartAttach = lspPermissionModel(1 << 1)
const lspPermissionInput = lspPermissionModel(1 << 2)
const lspPermissionMicrophone = lspPermissionModel(1 << 3)
const lspPermissionStopOwnStream = lspPermissionModel(1 << 4)
const lspPermissionQuitApplication = lspPermissionModel(1 << 5)
const lspPermissionControllerOutput = lspPermissionModel(1 << 6)
const lspCompetitionNeedsCapacity = computed(() =>
  config.value?.lsp_profile === 'competition' && Number(config.value?.lsp_competition_capacity_mbps) <= 0
)
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

    <template v-if="platform === 'windows'">
      <hr class="my-4" />
      <h3 class="h5">{{ $t('config.lsp') }}</h3>
      <p class="text-body-secondary">{{ $t('config.lsp_desc') }}</p>

      <Checkbox class="mb-3"
                id="lsp_enabled"
                locale-prefix="config"
                v-model="config.lsp_enabled"
                default="true"
      ></Checkbox>

      <div class="row g-3 mb-3">
        <div class="col-12 col-md-6">
          <label for="lsp_port" class="form-label">{{ $t('config.lsp_port') }}</label>
          <input id="lsp_port" v-model="config.lsp_port" class="form-control"
                 type="number" min="1" max="65535" placeholder="48030" />
          <div class="form-text">{{ $t('config.lsp_port_desc') }}</div>
        </div>
        <div class="col-12 col-md-6">
          <label for="lsp_profile" class="form-label">{{ $t('config.lsp_profile') }}</label>
          <select id="lsp_profile" v-model="config.lsp_profile" class="form-select">
            <option value="adaptive-low-latency">{{ $t('config.lsp_profile_adaptive_low_latency') }}</option>
            <option value="competition">{{ $t('config.lsp_profile_competition') }}</option>
          </select>
          <div class="form-text">{{ $t('config.lsp_profile_desc') }}</div>
        </div>
      </div>

      <div class="mb-3">
        <label for="lsp_competition_capacity_mbps" class="form-label">
          {{ $t('config.lsp_competition_capacity_mbps') }}
        </label>
        <input id="lsp_competition_capacity_mbps"
               v-model="config.lsp_competition_capacity_mbps"
               class="form-control"
               type="number"
               min="0"
               max="2147483647"
               placeholder="0" />
        <div class="form-text">{{ $t('config.lsp_competition_capacity_mbps_desc') }}</div>
        <div v-if="lspCompetitionNeedsCapacity" class="alert alert-warning mt-2 mb-0" role="alert">
          <TriangleAlert :size="20" /> {{ $t('config.lsp_competition_capacity_required') }}
        </div>
      </div>

      <fieldset class="mb-3" aria-describedby="lsp-pairing-permissions-help">
        <legend class="h6">{{ $t('config.lsp_pairing_permissions') }}</legend>
        <div class="row g-2">
          <div class="col-12 col-md-6 form-check">
            <input id="lsp_permission_browse" v-model="lspPermissionBrowse" class="form-check-input" type="checkbox" />
            <label for="lsp_permission_browse" class="form-check-label">{{ $t('config.lsp_permission_browse') }}</label>
          </div>
          <div class="col-12 col-md-6 form-check">
            <input id="lsp_permission_start_attach" v-model="lspPermissionStartAttach" class="form-check-input" type="checkbox" />
            <label for="lsp_permission_start_attach" class="form-check-label">{{ $t('config.lsp_permission_start_attach') }}</label>
          </div>
          <div class="col-12 col-md-6 form-check">
            <input id="lsp_permission_input" v-model="lspPermissionInput" class="form-check-input" type="checkbox" />
            <label for="lsp_permission_input" class="form-check-label">{{ $t('config.lsp_permission_input') }}</label>
          </div>
          <div class="col-12 col-md-6 form-check">
            <input id="lsp_permission_microphone" v-model="lspPermissionMicrophone" class="form-check-input" type="checkbox" />
            <label for="lsp_permission_microphone" class="form-check-label">{{ $t('config.lsp_permission_microphone') }}</label>
          </div>
          <div class="col-12 col-md-6 form-check">
            <input id="lsp_permission_stop_own_stream" v-model="lspPermissionStopOwnStream" class="form-check-input" type="checkbox" />
            <label for="lsp_permission_stop_own_stream" class="form-check-label">{{ $t('config.lsp_permission_stop_own_stream') }}</label>
          </div>
          <div class="col-12 col-md-6 form-check">
            <input id="lsp_permission_quit_application" v-model="lspPermissionQuitApplication" class="form-check-input" type="checkbox" />
            <label for="lsp_permission_quit_application" class="form-check-label">{{ $t('config.lsp_permission_quit_application') }}</label>
          </div>
          <div class="col-12 col-md-6 form-check">
            <input id="lsp_permission_controller_output" v-model="lspPermissionControllerOutput" class="form-check-input" type="checkbox" />
            <label for="lsp_permission_controller_output" class="form-check-label">{{ $t('config.lsp_permission_controller_output') }}</label>
          </div>
        </div>
        <div id="lsp-pairing-permissions-help" class="form-text mt-2">
          {{ $t('config.lsp_pairing_permissions_desc') }}
        </div>
      </fieldset>
    </template>

  </div>
</template>

<style scoped>

</style>
