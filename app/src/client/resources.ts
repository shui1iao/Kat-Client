import type { ResourceItem } from './types';
export interface ResourceUpdateFailure { item:ResourceItem; message:string }
/** A click owns one snapshot: one request per row, serial, failures do not stop
 * the remaining resources, including when its page has since unmounted. */
export async function updateResources(
  items:readonly ResourceItem[],
  refresh:(item:ResourceItem)=>Promise<unknown>,
  describe:(error:unknown,item:ResourceItem)=>string,
):Promise<ResourceUpdateFailure[]> {
  const failures:ResourceUpdateFailure[]=[];
  for(const item of [...items]) {
    try { await refresh(item); }
    catch(error) { failures.push({item,message:describe(error,item)}); }
  }
  return failures;
}
