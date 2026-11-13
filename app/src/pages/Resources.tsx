import { Rules } from './Rules';
import type { Client } from '../client/useClient';

export function Resources({ c }: { c: Client }) {
  return <Rules c={c} view="resources" />;
}
