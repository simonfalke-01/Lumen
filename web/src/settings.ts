import type { Option } from './components/ui'

/** One curated host setting. Keys are the configuration-file names; labels are what users see. */
export type SettingDefinition =
  | { key: string; label: string; type: 'switch' }
  | { key: string; label: string; type: 'select'; options: readonly Option<string>[] }
  | { key: string; label: string; type: 'number'; min: number; max: number; unit?: string; zeroLabel?: string }
  | { key: string; label: string; type: 'text'; placeholder?: string; monospace?: boolean }

export type SettingTab = 'general' | 'streaming' | 'network' | 'video' | 'audio' | 'input' | 'advanced'

/** Settings tabs in display order; each tab is a URL, /settings/<id>. */
export const settingTabs: readonly { id: SettingTab; label: string }[] = [
  { id: 'general', label: 'General' },
  { id: 'streaming', label: 'Streaming' },
  { id: 'network', label: 'Network' },
  { id: 'video', label: 'Video' },
  { id: 'audio', label: 'Audio' },
  { id: 'input', label: 'Input' },
  { id: 'advanced', label: 'Advanced' },
]

export interface SettingSection {
  id: string
  tab: SettingTab
  title: string
  settings: readonly SettingDefinition[]
  /** Shown only when another setting has a given value, such as one encoder's tuning. */
  visibleWhen?: { key: string; value: string }
}

const yesNoAuto = [
  { value: 'disabled', label: 'Off' },
  { value: 'auto', label: 'Automatic' },
  { value: 'manual', label: 'Manual' },
] as const

export const settingSections: readonly SettingSection[] = [
  {
    id: 'general',
    tab: 'general',
    title: 'General',
    settings: [
      { key: 'host_name', label: 'Host name', type: 'text' },
      { key: 'system_tray', label: 'Show in the system tray', type: 'switch' },
      {
        key: 'min_log_level',
        label: 'Log detail',
        type: 'select',
        options: [
          { value: 'verbose', label: 'Verbose' },
          { value: 'debug', label: 'Debug' },
          { value: 'info', label: 'Normal' },
          { value: 'warning', label: 'Warnings and errors' },
          { value: 'error', label: 'Errors only' },
        ],
      },
    ],
  },
  {
    id: 'streaming',
    tab: 'streaming',
    title: 'Lumen streaming',
    settings: [
      { key: 'lsp_enabled', label: 'Allow Lumen streaming', type: 'switch' },
      { key: 'lsp_port', label: 'UDP port', type: 'number', min: 1, max: 65535 },
      {
        key: 'lsp_profile',
        label: 'Network profile',
        type: 'select',
        options: [
          { value: 'adaptive-low-latency', label: 'Adaptive' },
          { value: 'competition', label: 'Competition (wired)' },
        ],
      },
      { key: 'lsp_competition_capacity_mbps', label: 'Competition link capacity', type: 'number', min: 0, max: 100000, unit: 'Mbps', zeroLabel: 'Not set' },
    ],
  },
  {
    id: 'network',
    tab: 'network',
    title: 'Network',
    settings: [
      { key: 'port', label: 'GameStream base port', type: 'number', min: 1029, max: 65514 },
      {
        key: 'address_family',
        label: 'Addresses',
        type: 'select',
        options: [
          { value: 'ipv4', label: 'IPv4 only' },
          { value: 'both', label: 'IPv4 and IPv6' },
        ],
      },
      { key: 'bind_address', label: 'Bind to address', type: 'text', placeholder: 'All addresses', monospace: true },
      { key: 'upnp', label: 'Open ports automatically with UPnP', type: 'switch' },
      { key: 'external_ip', label: 'Public address', type: 'text', placeholder: 'Detected automatically', monospace: true },
      {
        key: 'origin_web_ui_allowed',
        label: 'Allow this admin page from',
        type: 'select',
        options: [
          { value: 'pc', label: 'This PC only' },
          { value: 'lan', label: 'Local network' },
          { value: 'wan', label: 'Anywhere' },
        ],
      },
    ],
  },
  {
    id: 'video',
    tab: 'video',
    title: 'Video',
    settings: [
      {
        key: 'encoder',
        label: 'Encoder',
        type: 'select',
        options: [
          { value: '', label: 'Automatic' },
          { value: 'nvenc', label: 'NVIDIA NVENC' },
          { value: 'quicksync', label: 'Intel Quick Sync' },
          { value: 'amdvce', label: 'AMD AMF' },
          { value: 'software', label: 'Software' },
        ],
      },
      { key: 'adapter_name', label: 'GPU', type: 'text', placeholder: 'Automatic' },
      { key: 'output_name', label: 'Display', type: 'text', placeholder: 'Automatic', monospace: true },
      { key: 'max_bitrate', label: 'Maximum bitrate', type: 'number', min: 0, max: 1000000, unit: 'Kbps', zeroLabel: 'No limit' },
      { key: 'minimum_fps_target', label: 'Minimum frame rate', type: 'number', min: 0, max: 1000, unit: 'FPS', zeroLabel: 'Automatic' },
      {
        key: 'lumen_vdd_policy',
        label: 'Virtual display',
        type: 'select',
        options: [
          { value: 'disabled', label: 'Off' },
          { value: 'optional', label: 'Use when available' },
          { value: 'required', label: 'Required' },
        ],
      },
      {
        key: 'dd_configuration_option',
        label: 'Display while streaming',
        type: 'select',
        options: [
          { value: 'disabled', label: 'Leave as is' },
          { value: 'verify_only', label: 'Check it’s on' },
          { value: 'ensure_active', label: 'Turn it on' },
          { value: 'ensure_primary', label: 'Make it the main display' },
          { value: 'ensure_only_display', label: 'Make it the only display' },
        ],
      },
      { key: 'dd_resolution_option', label: 'Match device resolution', type: 'select', options: yesNoAuto },
      { key: 'dd_refresh_rate_option', label: 'Match device refresh rate', type: 'select', options: yesNoAuto },
      {
        key: 'dd_hdr_option',
        label: 'HDR',
        type: 'select',
        options: [
          { value: 'disabled', label: 'Leave as is' },
          { value: 'auto', label: 'Match the device' },
        ],
      },
    ],
  },
  {
    id: 'nvenc',
    tab: 'video',
    title: 'NVENC tuning',
    visibleWhen: { key: 'encoder', value: 'nvenc' },
    settings: [
      {
        key: 'nvenc_preset',
        label: 'Speed',
        type: 'select',
        options: [1, 2, 3, 4, 5, 6, 7].map((preset) => ({ value: String(preset), label: preset === 1 ? 'P1 (fastest)' : preset === 7 ? 'P7 (best quality)' : `P${preset}` })),
      },
      {
        key: 'nvenc_twopass',
        label: 'Two-pass encoding',
        type: 'select',
        options: [
          { value: 'disabled', label: 'Off' },
          { value: 'quarter_res', label: 'Quarter resolution' },
          { value: 'full_res', label: 'Full resolution' },
        ],
      },
      { key: 'nvenc_spatial_aq', label: 'Spatial adaptive quantization', type: 'switch' },
      { key: 'nvenc_latency_over_power', label: 'Prefer low latency over power saving', type: 'switch' },
    ],
  },
  {
    id: 'audio',
    tab: 'audio',
    title: 'Audio',
    settings: [
      { key: 'stream_audio', label: 'Stream audio', type: 'switch' },
      { key: 'audio_sink', label: 'Audio output', type: 'text', placeholder: 'Default output' },
      { key: 'virtual_sink', label: 'Virtual output', type: 'text', placeholder: 'None' },
      { key: 'client_microphone', label: 'Use device microphones', type: 'switch' },
      {
        key: 'client_microphone_sink',
        label: 'Microphone input',
        type: 'select',
        options: [
          { value: 'steam', label: 'Steam Streaming Microphone' },
          { value: 'vb-cable', label: 'VB-CABLE' },
          { value: 'lumen-driver', label: 'Lumen microphone' },
        ],
      },
    ],
  },
  {
    id: 'input',
    tab: 'input',
    title: 'Input',
    settings: [
      { key: 'keyboard', label: 'Keyboard', type: 'switch' },
      { key: 'mouse', label: 'Mouse', type: 'switch' },
      { key: 'controller', label: 'Controllers', type: 'switch' },
      {
        key: 'gamepad_backend',
        label: 'Controller driver',
        type: 'select',
        options: [
          { value: 'auto', label: 'Automatic' },
          { value: 'virtualhid', label: 'Lumen virtual controller' },
          { value: 'vigem', label: 'ViGEmBus' },
        ],
      },
      { key: 'high_resolution_scrolling', label: 'High-resolution scrolling', type: 'switch' },
      { key: 'native_pen_touch', label: 'Pen and touch', type: 'switch' },
      { key: 'key_rightalt_to_key_win', label: 'Use Right Alt as the Windows key', type: 'switch' },
    ],
  },
]

/** Keys rendered by a curated section; the rest appear under All settings. */
export const curatedKeys = new Set(settingSections.flatMap((section) => section.settings.map((setting) => setting.key)))

/** Keys that are files, credentials, or managed elsewhere and never edited as plain values. */
export const hiddenKeys = new Set(['pkey', 'cert', 'file_state', 'credentials_file', 'file_apps', 'log_path', 'lsp_pairing_permissions'])
