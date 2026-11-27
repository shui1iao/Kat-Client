import { Modal } from './Editors';
import { CopyButton } from './ui';
import { errorText, subscriptionAttemptLines } from '../lib/errors';

function operationErrorParts(error: string) {
  const text = errorText(error);
  const match = /（诊断码：([A-Za-z][A-Za-z0-9_]{1,63})）$/.exec(text);
  return { message: match ? text.slice(0, match.index) : text, code: match?.[1] ?? '' };
}

// Deliberately readOnly: dismissing an error does not capture or invalidate a
// configuration revision. The App owns the FIFO, never a stack.
export function OperationError({ error, close }: { error: string; close: () => void }) {
  const [message, diagnostic] = error.split('\n\n订阅安全诊断\n');
  const parts = operationErrorParts(message);
  const attempts = diagnostic ? subscriptionAttemptLines(diagnostic) : [];

  return (
    <Modal
      title="操作未完成"
      role="alertdialog"
      readOnly
      hideCancel
      noFieldset
      maskClassName="operation-error-mask"
      className="operation-error"
      close={close}
      save={close}
      saveLabel="知道了"
    >
      <p id="operation-error-message">{parts.message}</p>
      {parts.code && <p className="operation-error-code">诊断码：{parts.code}</p>}
      {attempts.length > 0 && (
        <ul className="subscription-attempts">
          {attempts.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>
      )}
      {diagnostic && (
        <>
          <details className="subscription-diagnostic">
            <summary>原始诊断</summary>
            <pre>{diagnostic}</pre>
          </details>
          <CopyButton text={diagnostic} label="复制诊断" className="subscription-copy-diagnostic" />
        </>
      )}
    </Modal>
  );
}
