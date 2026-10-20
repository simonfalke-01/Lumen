/**
 * Product primitives over React Aria Components. React Aria owns semantics, keyboard behavior,
 * focus management, and dismissal; these wrappers only bind tokens and product vocabulary.
 */
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import {
  Button as AriaButton,
  type ButtonProps as AriaButtonProps,
  Checkbox as AriaCheckbox,
  Dialog as AriaDialog,
  FieldError,
  Heading,
  Input,
  Label,
  ListBox,
  ListBoxItem,
  Modal,
  ModalOverlay,
  Popover,
  Select as AriaSelect,
  SelectValue,
  Switch as AriaSwitch,
  Text,
  TextField as AriaTextField,
  type TextFieldProps as AriaTextFieldProps,
} from 'react-aria-components'

type Tone = 'primary' | 'secondary' | 'quiet' | 'danger'

export function Button({ tone = 'secondary', className, ...props }: AriaButtonProps & { tone?: Tone }) {
  return <AriaButton {...props} className={['button', `button--${tone}`, className].filter(Boolean).join(' ')} />
}

export function IconButton({ label, children, ...props }: AriaButtonProps & { label: string; children: ReactNode }) {
  return (
    <AriaButton {...props} aria-label={label} className="icon-button">
      {children}
    </AriaButton>
  )
}

export function TextField({
  label,
  description,
  errorMessage,
  placeholder,
  type,
  monospace,
  ...props
}: AriaTextFieldProps & {
  label: string
  description?: string
  errorMessage?: string
  placeholder?: string
  monospace?: boolean
}) {
  return (
    <AriaTextField {...props} type={type} className="field">
      <Label className="field__label">{label}</Label>
      <Input className={monospace ? 'input input--mono' : 'input'} placeholder={placeholder} />
      {description && (
        <Text slot="description" className="field__description">
          {description}
        </Text>
      )}
      <FieldError className="field__error">{errorMessage}</FieldError>
    </AriaTextField>
  )
}

export function Switch({
  children,
  isSelected,
  onChange,
  isDisabled,
}: {
  children: ReactNode
  isSelected: boolean
  onChange: (value: boolean) => void
  isDisabled?: boolean
}) {
  return (
    <AriaSwitch className="switch" isSelected={isSelected} onChange={onChange} isDisabled={isDisabled}>
      <span className="switch__label">{children}</span>
      <span className="switch__track" aria-hidden>
        <span className="switch__thumb" />
      </span>
    </AriaSwitch>
  )
}

export function Checkbox({
  children,
  value,
  isDisabled,
}: {
  children: ReactNode
  value: string
  isDisabled?: boolean
}) {
  return (
    <AriaCheckbox className="checkbox" value={value} isDisabled={isDisabled}>
      <span className="checkbox__box" aria-hidden>
        <svg viewBox="0 0 12 12" className="checkbox__mark">
          <path d="M2.5 6.2 5 8.6 9.6 3.6" />
        </svg>
      </span>
      {children}
    </AriaCheckbox>
  )
}

export interface Option<T extends string> {
  value: T
  label: string
}

export function Select<T extends string>({
  label,
  options,
  value,
  onChange,
  isDisabled,
}: {
  label: string
  options: readonly Option<T>[]
  value: T
  onChange: (value: T) => void
  isDisabled?: boolean
}) {
  return (
    <AriaSelect
      className="select"
      selectedKey={value}
      onSelectionChange={(key) => onChange(key as T)}
      isDisabled={isDisabled}
      aria-label={label}
    >
      <AriaButton className="select__trigger">
        <SelectValue className="select__value">
          {({ selectedText }) => selectedText || 'Choose…'}
        </SelectValue>
        <svg viewBox="0 0 12 12" className="select__chevron" aria-hidden>
          <path d="M3 4.5 6 7.5 9 4.5" />
        </svg>
      </AriaButton>
      <Popover className="popover" offset={4}>
        <ListBox className="listbox" items={options.map((option) => ({ id: option.value, ...option }))}>
          {(option) => (
            <ListBoxItem className="listbox__item" id={option.id} textValue={option.label}>
              {option.label}
            </ListBoxItem>
          )}
        </ListBox>
      </Popover>
    </AriaSelect>
  )
}

/**
 * A focused task dialog. React Aria traps focus, restores it on close, and closes on Escape.
 */
export function Dialog({
  title,
  isOpen,
  onOpenChange,
  children,
  role,
  width = 'medium',
}: {
  title: string
  isOpen: boolean
  onOpenChange: (open: boolean) => void
  children: ReactNode | ((close: () => void) => ReactNode)
  role?: 'dialog' | 'alertdialog'
  width?: 'small' | 'medium' | 'large'
}) {
  return (
    <ModalOverlay className="modal-overlay" isOpen={isOpen} onOpenChange={onOpenChange} isDismissable={role !== 'alertdialog'}>
      <Modal className={`modal modal--${width}`}>
        <AriaDialog className="dialog" role={role}>
          {({ close }) => (
            <>
              <header className="dialog__header">
                <Heading slot="title" className="dialog__title">
                  {title}
                </Heading>
                {role !== 'alertdialog' && (
                  <IconButton label="Close" slot="close">
                    <X size={16} />
                  </IconButton>
                )}
              </header>
              {typeof children === 'function' ? children(close) : children}
            </>
          )}
        </AriaDialog>
      </Modal>
    </ModalOverlay>
  )
}

/** A destructive confirmation naming the object and consequence, with a safe cancel. */
export function ConfirmDialog({
  title,
  message,
  confirmLabel,
  isOpen,
  onOpenChange,
  onConfirm,
}: {
  title: string
  message: string
  confirmLabel: string
  isOpen: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: () => Promise<void> | void
}) {
  return (
    <Dialog title={title} isOpen={isOpen} onOpenChange={onOpenChange} role="alertdialog" width="small">
      {(close) => (
        <>
          <p className="dialog__message">{message}</p>
          <footer className="dialog__actions">
            <Button tone="secondary" onPress={close} autoFocus>
              Cancel
            </Button>
            <Button
              tone="danger"
              onPress={async () => {
                await onConfirm()
                close()
              }}
            >
              {confirmLabel}
            </Button>
          </footer>
        </>
      )}
    </Dialog>
  )
}

/** A persistent, polite status message for route-level problems. */
export function InlineAlert({ tone, children }: { tone: 'warning' | 'danger'; children: ReactNode }) {
  return (
    <div className={`inline-alert inline-alert--${tone}`} role={tone === 'danger' ? 'alert' : 'status'}>
      {children}
    </div>
  )
}
