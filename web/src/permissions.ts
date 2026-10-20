import type { Permission } from './api'

/** Every device permission, with the full label and a short noun for summaries. */
export const permissionOptions: readonly { value: Permission; label: string; short: string }[] = [
  { value: 'browse', label: 'See apps', short: 'app list' },
  { value: 'start', label: 'Start streams', short: 'streaming' },
  { value: 'input', label: 'Control keyboard, mouse, and controllers', short: 'input' },
  { value: 'stop', label: 'Stop its own stream', short: 'stopping streams' },
  { value: 'quit', label: 'Quit the app it started', short: 'quitting apps' },
  { value: 'microphone', label: 'Use its microphone on this PC', short: 'microphone' },
  { value: 'controller-output', label: 'Receive controller rumble and lights', short: 'controller feedback' },
  { value: 'clipboard', label: 'Share the clipboard', short: 'clipboard' },
]

/** One short phrase for a permission set, for lists where the full set would be noise. */
export function permissionSummary(permissions: readonly Permission[]) {
  if (!permissions.includes('start')) return 'Can’t stream'
  const missing = permissionOptions.filter((option) => !permissions.includes(option.value)).map((option) => option.short)
  if (missing.length === 0) return 'Full access'
  if (missing.length <= 2) return `All except ${missing.join(' and ')}`
  return `${permissions.length} of ${permissionOptions.length} permissions`
}
