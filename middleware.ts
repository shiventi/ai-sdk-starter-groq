// middleware.ts -> a simple firewall for my vercel app
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { kv } from '@vercel/kv';

// firewall config
const CONFIG = {
  // rate limit for random internet traffic
  rateLimit: {
    limit: 30,
    window: 20,
  },
  // my own services can use these keys to bypass the rate limit
  trustedKeys: [
    'k$tF_8#Z!pQvY7@eR_wJ6x*uG9hL4m&',
    's3C!bN_9^zP_qR$tW*vXyZ_2&4@6*8(0',
  ],
  allowedPaths: [] as string[], 
};

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  
  if (CONFIG.allowedPaths.includes(pathname)) {
    return NextResponse.next();
  }

  // check for a trusted key (the vip pass)
  const authHeader = req.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '');
  if (CONFIG.trustedKeys.includes(token)) {
    return NextResponse.next();
  }

  // if not trusted, run the ip rate limit
  const ip = req.headers.get('cf-connecting-ip') ?? req.headers.get('x-forwarded-for') ?? '127.0.0.1';
  const key = `ratelimit:${ip}`;

  try {
    const count = await kv.incr(key);

    if (count === 1) {
      // set the expiration on the first request
      await kv.expire(key, CONFIG.rateLimit.window);
    }

    if (count > CONFIG.rateLimit.limit) {
      return new NextResponse('rate limit exceeded', { status: 429 });
    }
  } catch (err) {
    // if kv fails, let the request through
    console.error("firewall error:", err);
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: '/((?!_next/static|_next/image|favicon.ico).*)',
};