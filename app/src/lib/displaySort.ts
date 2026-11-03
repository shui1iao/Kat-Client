import { useState } from 'react';
import type { DisplaySort } from '../client/settings';
export function useDisplaySort(scope:'nodes'|'members'):[DisplaySort,(v:DisplaySort)=>void]{
 const key='kat.displaySort.'+scope;
 const [value,setValue]=useState<DisplaySort>(()=>{try{const s=localStorage.getItem(key);return s==='name'||s==='latency'?s:'config';}catch{return 'config';}});
 return [value,v=>{setValue(v);try{localStorage.setItem(key,v);}catch{}}];
}
