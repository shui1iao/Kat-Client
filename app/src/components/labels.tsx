import type {CSSProperties} from 'react';
import {parseConnectionRule,ruleColor} from '../client/presentation';
import {tip} from './Tooltip';
export function KTag({label,color,className=''}:{label:string;color:string;className?:string}){return <span className={'ktag '+className} style={{'--tag-color':color} as CSSProperties}>{label}</span>;}
export function NetworkTag({network}:{network:string}){return <KTag className="network-tag" label={network?network.toUpperCase():'—'} color={network==='udp'?'#8B5CF6':'#3B82F6'}/>;}
export function RuleTag({type}:{type:string}){return <KTag label={type} color={ruleColor(type)}/>;}
export function ConnectionRule({raw}:{raw:string}){const p=parseConnectionRule(raw);return <span className="conn-rule" {...tip(raw)}>{p?<><RuleTag type={p.type}/>{p.payload&&<span className="rule-payload">{p.payload}</span>}</>:raw||'—'}</span>;}
export function KState({tone,label,title}:{tone:'ok'|'warn'|'bad';label:string;title?:string}){return <span className={'kstate '+tone} {...tip(title&&title!==label?title:undefined)}><i/>{label}</span>;}

export function ConnectionTarget({name,title,sniffed}:{name:string;title?:string;sniffed?:boolean}){return <span className="conn-target"><span className="conn-name" {...tip(title&&title!==name?title:name,!(title&&title!==name))}>{name||'—'}</span>{sniffed&&<small className="sniff-label" {...tip('嗅探得到的域名')}>嗅探</small>}</span>;}
