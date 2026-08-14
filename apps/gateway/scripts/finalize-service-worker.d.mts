export interface FinalizedServiceWorker {
  cacheName: string;
  urls: string[];
}

export function finalizeServiceWorker(
  distRoot?: string,
): Promise<FinalizedServiceWorker>;
