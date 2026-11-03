// Only core-generated, sniffed data URIs are stored. No URL or file is fetched
// by WebView; the map survives page unmounts for the entire App lifetime.
const images=new Map<string,string>();
export const validCachedImage=(uri:unknown):uri is string=>typeof uri==='string'&&/^data:image\/(png|jpeg|webp|gif|x-icon|vnd\.microsoft\.icon|svg\+xml);base64,/.test(uri);
export const cachedIcon=(url:string)=>images.get(url)??'';
export function rememberIcon(url:string,uri:string){if(validCachedImage(uri))images.set(url,uri);}
export const forgetIcon=(url:string)=>images.delete(url);
export function hydrateIcons(table:Record<string,string>){for(const [url,uri]of Object.entries(table))rememberIcon(url,uri);}

let active=0;const waiting:(()=>void)[]=[];const pending=new Map<string,Promise<string>>();
export function requestIcon(url:string,group:string):Promise<string>{
 const cached=cachedIcon(url);if(cached)return Promise.resolve(cached);
 const prior=pending.get(url);if(prior)return prior;
 const work=(async()=>{if(active<4)active++;else await new Promise<void>(r=>waiting.push(r));try{const {core}=await import('./ipc');const r=await core<{data_uri:string}>('icon.get',{url,group});rememberIcon(url,r.data_uri);return r.data_uri;}finally{const next=waiting.shift();if(next)next();else active--;}})();
 pending.set(url,work);void work.finally(()=>pending.delete(url)).catch(()=>{});return work;
}
