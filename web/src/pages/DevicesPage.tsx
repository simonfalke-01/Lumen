import { MoreHorizontal } from 'lucide-react'
import { useState } from 'react'
import { Button as AriaButton, CheckboxGroup, Form, Menu, MenuItem, MenuTrigger, Popover, Separator } from 'react-aria-components'
import { api, ApiError, type Device, type Permission } from '../api'
import { Button, Checkbox, ConfirmDialog, Dialog, InlineAlert, TextField } from '../components/ui'
import { permissionOptions, permissionSummary } from '../permissions'
import { useResource } from '../useResource'

type DeviceDialog = { kind: 'rename' | 'permissions' | 'remove'; device: Device } | { kind: 'gamestream' } | null

export function DevicesPage() {
  const devices = useResource(api.devices)
  const [dialog, setDialog] = useState<DeviceDialog>(null)
  const [error, setError] = useState<string>()
  const list = devices.data?.devices ?? []

  const update = async (device: Device, change: Partial<Pick<Device, 'name' | 'enabled' | 'permissions'>>) => {
    setError(undefined)
    try {
      const updated = await api.updateDevice(device, change)
      devices.setData((current) =>
        current && { devices: current.devices.map((entry) => (sameDevice(entry, device) ? updated : entry)) },
      )
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The change wasn’t saved.')
      throw caught
    }
  }

  return (
    <div className="page">
      <header className="page__header">
        <h1 className="page__title">Devices</h1>
        <Button tone="secondary" onPress={() => setDialog({ kind: 'gamestream' })}>
          Enter GameStream PIN…
        </Button>
      </header>

      {error && <InlineAlert tone="danger">{error}</InlineAlert>}
      {devices.error && !devices.data && <InlineAlert tone="danger">{devices.error.message}</InlineAlert>}

      {devices.data && list.length === 0 && (
        <p className="quiet">No devices are paired. Start pairing from Umbra on the device you want to add.</p>
      )}

      {list.length > 0 && (
        <ul className="ledger" aria-label="Paired devices">
          {list.map((device) => (
            <li key={`${device.protocol}:${device.id}`} className="ledger__row">
              <div className="ledger__main">
                <span className="ledger__name">{device.name}</span>
                <span className="ledger__meta">
                  {device.protocol === 'gamestream'
                    ? 'GameStream'
                    : device.permissions && permissionSummary(device.permissions)}
                </span>
              </div>
              {!device.enabled && <span className="badge">Disabled</span>}
              <MenuTrigger>
                <AriaButton className="icon-button" aria-label={`Actions for ${device.name}`}>
                  <MoreHorizontal size={16} aria-hidden />
                </AriaButton>
                <Popover className="popover" placement="bottom end" offset={4}>
                  <Menu className="menu">
                    <MenuItem className="menu__item" onAction={() => setDialog({ kind: 'rename', device })}>
                      Rename…
                    </MenuItem>
                    {device.protocol === 'lsp' && (
                      <MenuItem className="menu__item" onAction={() => setDialog({ kind: 'permissions', device })}>
                        Permissions…
                      </MenuItem>
                    )}
                    <MenuItem
                      className="menu__item"
                      onAction={() => void update(device, { enabled: !device.enabled }).catch(() => undefined)}
                    >
                      {device.enabled ? 'Disable' : 'Enable'}
                    </MenuItem>
                    <Separator className="menu__separator" />
                    <MenuItem className="menu__item menu__item--danger" onAction={() => setDialog({ kind: 'remove', device })}>
                      Remove…
                    </MenuItem>
                  </Menu>
                </Popover>
              </MenuTrigger>
            </li>
          ))}
        </ul>
      )}

      {dialog?.kind === 'rename' && (
        <RenameDialog device={dialog.device} onClose={() => setDialog(null)} onSave={(name) => update(dialog.device, { name })} />
      )}
      {dialog?.kind === 'permissions' && (
        <PermissionsDialog
          device={dialog.device}
          onClose={() => setDialog(null)}
          onSave={(permissions) => update(dialog.device, { permissions })}
        />
      )}
      {dialog?.kind === 'remove' && (
        <ConfirmDialog
          title={`Remove ${dialog.device.name}?`}
          message="The device can no longer stream from this PC. It has to pair again to come back."
          confirmLabel="Remove"
          isOpen
          onOpenChange={(open) => !open && setDialog(null)}
          onConfirm={async () => {
            await api.removeDevice(dialog.device)
            await devices.reload()
          }}
        />
      )}
      {dialog?.kind === 'gamestream' && <GameStreamPinDialog onClose={() => setDialog(null)} onPaired={devices.reload} />}
    </div>
  )
}

function sameDevice(left: Device, right: Device) {
  return left.id === right.id && left.protocol === right.protocol
}

function RenameDialog({ device, onClose, onSave }: { device: Device; onClose: () => void; onSave: (name: string) => Promise<void> }) {
  const [name, setName] = useState(device.name)
  const trimmed = name.trim()
  return (
    <Dialog title="Rename Device" isOpen onOpenChange={(open) => !open && onClose()} width="small">
      {(close) => (
        <Form
          className="dialog__form"
          onSubmit={(event) => {
            event.preventDefault()
            if (trimmed) void onSave(trimmed).then(close, () => undefined)
          }}
        >
          <TextField label="Name" value={name} onChange={setName} autoFocus isRequired maxLength={64} />
          <footer className="dialog__actions">
            <Button tone="secondary" onPress={close}>
              Cancel
            </Button>
            <Button tone="primary" type="submit" isDisabled={!trimmed}>
              Rename
            </Button>
          </footer>
        </Form>
      )}
    </Dialog>
  )
}

function PermissionsDialog({
  device,
  onClose,
  onSave,
}: {
  device: Device
  onClose: () => void
  onSave: (permissions: Permission[]) => Promise<void>
}) {
  const [selected, setSelected] = useState<string[]>(device.permissions ?? [])
  return (
    <Dialog title={`${device.name} Permissions`} isOpen onOpenChange={(open) => !open && onClose()}>
      {(close) => (
        <Form
          className="dialog__form"
          onSubmit={(event) => {
            event.preventDefault()
            void onSave(selected as Permission[]).then(close, () => undefined)
          }}
        >
          <CheckboxGroup className="checkbox-group" aria-label="Permissions" value={selected} onChange={setSelected}>
            {permissionOptions.map((option) => (
              <Checkbox key={option.value} value={option.value}>
                {option.label}
              </Checkbox>
            ))}
          </CheckboxGroup>
          <p className="quiet">The device reconnects once with the new permissions.</p>
          <footer className="dialog__actions">
            <Button tone="secondary" onPress={close}>
              Cancel
            </Button>
            <Button tone="primary" type="submit" isDisabled={selected.length === 0}>
              Save
            </Button>
          </footer>
        </Form>
      )}
    </Dialog>
  )
}

/** GameStream clients show a PIN on the device; the administrator types it here. */
function GameStreamPinDialog({ onClose, onPaired }: { onClose: () => void; onPaired: () => Promise<void> }) {
  const [pin, setPin] = useState('')
  const [name, setName] = useState('')
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const valid = /^\d{4}$/.test(pin) && name.trim().length > 0

  return (
    <Dialog title="Enter GameStream PIN" isOpen onOpenChange={(open) => !open && onClose()} width="small">
      {(close) => (
        <Form
          className="dialog__form"
          onSubmit={(event) => {
            event.preventDefault()
            if (!valid) return
            setBusy(true)
            setError(undefined)
            api
              .pairGameStream(pin, name.trim())
              .then(onPaired)
              .then(close)
              .catch((caught) => setError(caught instanceof ApiError ? caught.message : 'Pairing failed. Try again.'))
              .finally(() => setBusy(false))
          }}
        >
          {error && <InlineAlert tone="danger">{error}</InlineAlert>}
          <TextField
            label="PIN"
            value={pin}
            onChange={(value) => setPin(value.replace(/\D/g, '').slice(0, 4))}
            inputMode="numeric"
            placeholder="0000"
            monospace
            autoFocus
          />
          <TextField label="Device name" value={name} onChange={setName} maxLength={64} />
          <footer className="dialog__actions">
            <Button tone="secondary" onPress={close}>
              Cancel
            </Button>
            <Button tone="primary" type="submit" isDisabled={!valid} isPending={busy}>
              Pair
            </Button>
          </footer>
        </Form>
      )}
    </Dialog>
  )
}
