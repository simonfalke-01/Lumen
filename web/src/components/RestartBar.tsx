import { usePresence } from './usePresence'
import { Button } from './ui'

/** Exit duration in ms; matches --duration-exit. */
const EXIT_MS = 130

/**
 * Floating notice that rises from the bottom of the content area when a saved change needs a
 * restart. It stays until the user restarts or chooses Later.
 */
export function RestartBar({
  open,
  restarting,
  onRestart,
  onLater,
}: {
  open: boolean
  restarting: boolean
  onRestart: () => void
  onLater: () => void
}) {
  const presence = usePresence(open, EXIT_MS)
  if (!presence.mounted) return null
  return (
    <div className="restart-bar" data-presence={presence.state} role="status">
      <span className="restart-bar__message">
        {restarting ? 'Restarting Lumen…' : 'Some changes take effect after Lumen restarts.'}
      </span>
      <div className="restart-bar__actions">
        <Button tone="quiet" onPress={onLater} isDisabled={restarting}>
          Later
        </Button>
        <Button tone="primary" onPress={onRestart} isDisabled={restarting}>
          Restart Now
        </Button>
      </div>
    </div>
  )
}
