import { useEffect, useRef, useState } from 'react';
import { Modal } from './Editors';
export function useConfirmation() {
 const [question,setQuestion]=useState<string|null>(null),resolver=useRef<((ok:boolean)=>void)|null>(null);
 const answer=(ok:boolean)=>{resolver.current?.(ok);resolver.current=null;setQuestion(null);};
 useEffect(()=>()=>{resolver.current?.(false);},[]);
 const confirm=(title:string)=>new Promise<boolean>(resolve=>{resolver.current?.(false);resolver.current=resolve;setQuestion(title);});
 return {confirm,dialog:question?<Modal size="sm" title={question} close={()=>answer(false)} save={()=>answer(true)} saveLabel="确认"><></></Modal>:null};
}
