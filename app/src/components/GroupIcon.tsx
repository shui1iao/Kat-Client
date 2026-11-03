import {cachedIcon,rememberIcon,forgetIcon,validCachedImage,requestIcon} from '../client/iconCache';
import {useEffect,useState,useRef} from 'react';
import {Icon} from './Icon';
const failures=new Map<string,{at:number;running:boolean}>();
export function GroupIcon({value,type,group='',running=false}:{value?:string;type:string;group?:string;running?:boolean}){
 const [src,setSrc]=useState(()=>value?cachedIcon(value):''),[attempt,setAttempt]=useState(0);const previousRunning=useRef(running);
 useEffect(()=>{
  let live=true,timer:ReturnType<typeof setTimeout>|undefined;const started=running&&!previousRunning.current;previousRunning.current=running;if(!value){setSrc('');return;}
  const cached=cachedIcon(value);if(cached){setSrc(cached);return;}
  setSrc('');
  const retry=(delay=60000)=>{timer=setTimeout(()=>{if(live)setAttempt(n=>n+1)},delay)};
  const cleanup=()=>{live=false;clearTimeout(timer)};
  const prior=failures.get(value);if(prior&&Date.now()-prior.at<60000&&!started&&!(running&&!prior.running)){retry(60000-(Date.now()-prior.at));return cleanup;}
  void requestIcon(value,group).then(uri=>{if(!live)return;if(validCachedImage(uri)){failures.delete(value);rememberIcon(value,uri);setSrc(uri);}else {failures.set(value,{at:Date.now(),running});retry();}}).catch(()=>{if(live){failures.set(value,{at:Date.now(),running});retry();}});return cleanup;
 },[value,group,running,attempt]);
 return src?<img className="pc-image" src={src} alt="" onError={()=>{if(value){forgetIcon(value);failures.set(value,{at:Date.now(),running});}setSrc('');setAttempt(n=>n+1);}}/>:<span className={'card-glyph pc-glyph t-'+type} aria-hidden="true"><Icon name="policies" size={16}/></span>;
}
