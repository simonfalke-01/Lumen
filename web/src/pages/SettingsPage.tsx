import { useEffect, useState } from 'react'
import { Tab, TabList, TabPanel, Tabs } from 'react-aria-components'
import { api, ApiError, type SettingValue, type Settings } from '../api'
import { Button, ConfirmDialog, InlineAlert, Select, Switch } from '../components/ui'
import { navigate } from '../router'
import { curatedKeys, hiddenKeys, type SettingDefinition, settingSections, type SettingTab, settingTabs } from '../settings'
import { useResource } from '../useResource'

export function SettingsPage({ section, onChanged }: { section: string; onChanged: () => Promise<void> }) {
  const settings = useResource(api.settings)
  const [error, setError] = useState<string>()
  const [rotateOpen, setRotateOpen] = useState(false)
  const tab: SettingTab = settingTabs.some((entry) => entry.id === section) ? (section as SettingTab) : 'general'

  const change = async (key: string, value: SettingValue | null) => {
    setError(undefined)
    try {
      const updated = await api.updateSettings({ [key]: value })
      settings.setData(() => updated)
      await onChanged()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The setting wasn’t saved.')
    }
  }

  return (
    <div className="page">
      <h1 className="page__title">Settings</h1>
      <Tabs
        className="tabs"
        selectedKey={tab}
        onSelectionChange={(key) => navigate(key === 'general' ? '/settings' : `/settings/${String(key)}`, { keepScroll: true })}
      >
        <TabList className="tabs__list" aria-label="Settings">
          {settingTabs.map((entry) => (
            <Tab key={entry.id} id={entry.id} className="tabs__tab">
              {entry.label}
            </Tab>
          ))}
        </TabList>
        {error && <InlineAlert tone="danger">{error}</InlineAlert>}
        {settings.error && !settings.data && <InlineAlert tone="danger">{settings.error.message}</InlineAlert>}
        {settings.data &&
          settingTabs.map((entry) => (
            <TabPanel key={entry.id} id={entry.id} className="tabs__panel">
              {entry.id === 'advanced' ? (
                <AdvancedSettings settings={settings.data!} onChange={change} />
              ) : (
                <>
                  {settingSections
                    .filter((candidate) => candidate.tab === entry.id)
                    .filter(
                      (candidate) =>
                        !candidate.visibleWhen ||
                        String(settings.data!.values[candidate.visibleWhen.key] ?? settings.data!.defaults[candidate.visibleWhen.key] ?? '') ===
                          candidate.visibleWhen.value,
                    )
                    .map((candidate) => (
                      <section key={candidate.id} className="section" aria-label={candidate.title}>
                        {candidate.title !== entry.label && <h2 className="section__title">{candidate.title}</h2>}
                        <div className="settings-list">
                          {candidate.settings.map((definition) => (
                            <SettingRow key={definition.key} definition={definition} settings={settings.data!} onChange={change} />
                          ))}
                        </div>
                      </section>
                    ))}
                  {entry.id === 'streaming' && (
                    <section className="section" aria-label="Security">
                      <h2 className="section__title">Security</h2>
                      <div className="settings-list">
                        <div className="setting">
                          <span className="setting__label">Host certificate</span>
                          <div className="setting__control">
                            <Button tone="secondary" onPress={() => setRotateOpen(true)}>
                              Replace Certificate…
                            </Button>
                          </div>
                        </div>
                      </div>
                    </section>
                  )}
                </>
              )}
            </TabPanel>
          ))}
      </Tabs>

      <ConfirmDialog
        title="Replace the host certificate?"
        message="Paired Lumen devices accept the new certificate the next time they connect. Devices that are offline for a long time may need to pair again."
        confirmLabel="Replace Certificate"
        isOpen={rotateOpen}
        onOpenChange={setRotateOpen}
        onConfirm={async () => {
          try {
            await api.rotateIdentity()
          } catch (caught) {
            setError(caught instanceof ApiError ? caught.message : 'The certificate wasn’t replaced.')
          }
        }}
      />
    </div>
  )
}

/** Every setting without a curated control, by its configuration name. */
function AdvancedSettings({
  settings,
  onChange,
}: {
  settings: Settings
  onChange: (key: string, value: SettingValue | null) => Promise<void>
}) {
  const keys = Object.keys(settings.values)
    .filter((key) => !curatedKeys.has(key) && !hiddenKeys.has(key))
    .sort()
  if (keys.length === 0) {
    return <p className="quiet">Every setting in lumen.conf has a control on another tab.</p>
  }
  return (
    <div className="settings-list">
      {keys.map((key) => (
        <SettingRow
          key={key}
          definition={{ key, label: key, type: typeof settings.values[key] === 'boolean' ? 'switch' : 'text', monospace: true }}
          settings={settings}
          onChange={onChange}
          monospaceLabel
        />
      ))}
    </div>
  )
}

function SettingRow({
  definition,
  settings,
  onChange,
  monospaceLabel,
}: {
  definition: SettingDefinition
  settings: Settings
  onChange: (key: string, value: SettingValue | null) => Promise<void>
  monospaceLabel?: boolean
}) {
  const value = settings.values[definition.key] ?? settings.defaults[definition.key]
  const labelID = `setting-${definition.key}`

  return (
    <div className="setting">
      <span id={labelID} className={monospaceLabel ? 'setting__label mono' : 'setting__label'}>
        {definition.label}
      </span>
      <div className="setting__control">
        {definition.type === 'switch' && (
          <Switch isSelected={value === true || value === 'enabled' || value === 'true'} onChange={(next) => void onChange(definition.key, next)}>
            <span className="visually-hidden">{definition.label}</span>
          </Switch>
        )}
        {definition.type === 'select' && (
          <Select
            label={definition.label}
            options={definition.options}
            value={String(value ?? '')}
            onChange={(next) => void onChange(definition.key, next)}
          />
        )}
        {(definition.type === 'number' || definition.type === 'text') && (
          <CommitField
            labelID={labelID}
            value={
              value === undefined || (definition.type === 'number' && definition.zeroLabel && Number(value) === 0)
                ? ''
                : String(value)
            }
            placeholder={definition.type === 'text' ? definition.placeholder : definition.zeroLabel}
            numeric={definition.type === 'number'}
            monospace={definition.type === 'text' && definition.monospace}
            unit={definition.type === 'number' ? definition.unit : undefined}
            validate={(text) => {
              if (definition.type !== 'number' || text === '') return undefined
              const number = Number(text)
              return Number.isFinite(number) && number >= definition.min && number <= definition.max
                ? undefined
                : `Enter a number from ${definition.min} to ${definition.max}.`
            }}
            onCommit={(text) => {
              if (definition.type === 'number') return onChange(definition.key, text === '' ? null : Number(text))
              return onChange(definition.key, text === '' ? null : text)
            }}
          />
        )}
      </div>
    </div>
  )
}

/** A text input that saves on Enter or blur, keeps the draft on failure, and validates inline. */
function CommitField({
  labelID,
  value,
  placeholder,
  numeric,
  monospace,
  unit,
  validate,
  onCommit,
}: {
  labelID: string
  value: string
  placeholder?: string
  numeric: boolean
  monospace?: boolean
  unit?: string
  validate: (text: string) => string | undefined
  onCommit: (text: string) => Promise<void>
}) {
  const [draft, setDraft] = useState(value)
  const [invalid, setInvalid] = useState<string>()
  useEffect(() => setDraft(value), [value])

  const commit = () => {
    const text = draft.trim()
    const problem = validate(text)
    setInvalid(problem)
    if (problem || text === value) return
    void onCommit(text)
  }

  return (
    <div className="commit-field">
      <div className={unit ? 'commit-field__row commit-field__row--unit' : 'commit-field__row'}>
        <input
          aria-labelledby={labelID}
          aria-invalid={invalid ? true : undefined}
          className={monospace ? 'input input--mono' : 'input'}
          value={draft}
          placeholder={placeholder}
          inputMode={numeric ? 'numeric' : undefined}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={commit}
          onKeyDown={(event) => {
            if (event.key === 'Enter') commit()
            if (event.key === 'Escape') {
              setDraft(value)
              setInvalid(undefined)
            }
          }}
        />
        {unit && <span className="commit-field__unit">{unit}</span>}
      </div>
      {invalid && <span className="field__error">{invalid}</span>}
    </div>
  )
}
