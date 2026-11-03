import { useMemo, useState } from 'react';
import { Icon } from './Icon';
import { useFormDraft } from '../lib/formDraft';
import { Card } from './ui';
import { Field, LocalError } from './Editors';
import { desktopExtras, validateBypass } from '../client/settings';
import type { Client } from '../client/useClient';
export function ProxyBypass({c}:{c:Client}){const p=c.desktop?.preferences;return <Card title={<><span className="pg-title-icon c-indigo"><Icon name="shield" size={14}/></span>系统代理绕过</>} icon="shield" extra={<span className="card-note">下次启用生效</span>}>{p?<BypassForm c={c}/>:<div className="empty">未连接</div>}</Card>;}
function BypassForm({c}:{c:Client}){
 const accepted=useMemo(()=>{const p=desktopExtras(c.desktop!.preferences);return {mode:p.proxy_bypass_mode,value:p.proxy_bypass};},[c.desktop]);
 const draft=useFormDraft(accepted),{mode,value}=draft.value,dirty=draft.changed.size>0;
 const [error,setError]=useState('');
 return <form className="daily-network bypass-settings" onSubmit={async e=>{e.preventDefault();setError('');try{validateBypass(value);await draft.save(v=>c.setPreferences({proxy_bypass_mode:v.mode,proxy_bypass:v.value}),true);}catch(e){setError((e as Error).message);}}}>
 <Field label="绕过模式"><select className="inp" value={mode} disabled={c.busy.has('preferences')} onChange={e=>{draft.set('mode',e.target.value as typeof mode);}}><option value="inherit">沿用 Windows 原值</option><option value="custom">自定义</option></select></Field>
 {mode==='custom'&&<Field label="绕过规则（分号 / 通配符）"><textarea className="inp" maxLength={32768} spellCheck={false} value={value} onChange={e=>{draft.set('value',e.target.value);}}/></Field>}
 <LocalError text={error}/><div className="row-actions"><button className="btn primary" disabled={!dirty||c.busy.has('preferences')}>保存绕过设置</button><button className="btn" type="button" disabled={!dirty||c.busy.has('preferences')} onClick={()=>{draft.reset();setError('');}}>取消更改</button></div>
 </form>;
}
