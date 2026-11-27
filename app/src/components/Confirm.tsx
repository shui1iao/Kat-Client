import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Modal } from './Editors';

/** Shared compact confirmation dialog (used for deletes, destructive actions, and Confirm hook). */
export function ConfirmModal({
  title,
  close,
  onConfirm,
  confirmLabel = '确认',
  danger = false,
  busy = false,
  readOnly = false,
  children,
}: {
  title: string;
  close: () => void;
  onConfirm: () => void;
  confirmLabel?: string;
  danger?: boolean;
  busy?: boolean;
  readOnly?: boolean;
  children?: ReactNode;
}) {
  return (
    <Modal
      size="sm"
      title={title}
      close={close}
      save={onConfirm}
      saveLabel={confirmLabel}
      danger={danger}
      busy={busy}
      readOnly={readOnly}
    >
      {children ?? null}
    </Modal>
  );
}

export function useConfirmation() {
  const [question, setQuestion] = useState<string | null>(null);
  const resolver = useRef<((ok: boolean) => void) | null>(null);
  const answer = (ok: boolean) => {
    resolver.current?.(ok);
    resolver.current = null;
    setQuestion(null);
  };
  useEffect(
    () => () => {
      resolver.current?.(false);
    },
    [],
  );
  const confirm = (title: string) =>
    new Promise<boolean>((resolve) => {
      resolver.current?.(false);
      resolver.current = resolve;
      setQuestion(title);
    });
  return {
    confirm,
    dialog: question ? <ConfirmModal title={question} close={() => answer(false)} onConfirm={() => answer(true)} /> : null,
  };
}
