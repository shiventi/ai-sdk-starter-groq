// middleware.ts -> a simple firewall for my vercel app
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { kv } from '@vercel/kv';

// firewall config
const CONFIG = {
  // limit for random internet traffic
  ipRateLimit: {
    limit: 30,
    window: 20, // seconds
  },

  // my own services can use these keys to bypass the ip limit
  trustedKeys: [
    'k$tF_8#Z!pQvY7@eR_wJ6x*uG9hL4m&',
    's3C!bN_9^zP_qR$tW*vXyZ_2&4@6*8(0',
  ],

  // paths to ignore completely
  allowedPaths: [] as string[], 
};

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  
  if (CONFIG.allowedPaths.includes(pathname)) {
    return NextResponse.next();
  }

  // first, check if it's a worker trying to connect
  const isWorker = req.headers.has('cf-worker');
  
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  const isTrusted = CONFIG.trustedKeys.includes(token) && token !== '';

  if (isWorker) {
    if (isTrusted) {
      // its a worker we trust, let it pass without an ip limit
      return NextResponse.next();
    } else {
      // its an unknown worker, block it immediately
      return new NextResponse('untrusted worker', { status: 403 });
    }
  }

  // if its not a worker, treat as normal traffic and run the ip rate limit
  const ip = req.headers.get('cf-connecting-ip') ?? req.headers.get('x-forwarded-for') ?? '127.0.0.1';
  const key = `ratelimit:${ip}`;

  try {
    const count = await kv.incr(key);

    if (count === 1) {
      // set expiration on the first request in a new window
      await kv.expire(key, CONFIG.ipRateLimit.window);
    }

    if (count > CONFIG.ipRateLimit.limit) {
      return new NextResponse('rate limit exceeded', { status: 429 });
    }
  } catch (err) {
    // if kv fails, safer to let traffic through
    console.error("firewall error:", err);
  }
  
  return NextResponse.next();
}

// run on all paths except for static assets
export const config = {
  matcher: '/((?!_next/static|_next/image|favicon.ico).*)',
};