// middleware.ts -> The Vercel Shield: A Simple, Configurable Firewall (Definitive Version)
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { kv } from '@vercel/kv';

// --- MAIN CONFIGURATION ---
// tweak these settings to your needs
const FIREWALL_CONFIG = {
  
  // block all requests coming from any cloudflare worker?
  blockWorkers: {
    enabled: false, 
  },

  // rate limit settings
  rateLimit: {
    enabled: true,
    // how many requests are allowed...
    limit: 20,
    // ...in this time window (in seconds).
    window: 15, 
  },

  // an array of paths to exclude from the firewall.
  allowedPaths: [] as string[], 

};
// --- END OF CONFIGURATION ---

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  
  if (FIREWALL_CONFIG.allowedPaths.includes(pathname)) {
    return NextResponse.next();
  }

  if (FIREWALL_CONFIG.blockWorkers.enabled && req.headers.has('cf-worker')) {
    return new NextResponse('Forbidden: Direct worker access is not permitted.', { status: 403 });
  }

  if (FIREWALL_CONFIG.rateLimit.enabled) {
    const ip = req.headers.get('cf-connecting-ip') ?? req.headers.get('x-forwarded-for') ?? '127.0.0.1';
    const key = `ratelimit:${ip}`;

    try {
      // --- THE DEFINITIVE FIX IS HERE ---
      // This is the most robust and type-safe pattern for rate limiting.
      
      // 1. Increment the counter for the IP. This is an atomic operation.
      //    It returns the new value of the counter.
      const currentRequests = await kv.incr(key);

      // 2. If this is the first request, set the expiration for the key.
      //    This creates our "time window".
      if (currentRequests === 1) {
        await kv.expire(key, FIREWALL_CONFIG.rateLimit.window);
      }

      // 3. Now, check if the count has exceeded the limit.
      if (currentRequests > FIREWALL_CONFIG.rateLimit.limit) {
        return new NextResponse('Rate limit exceeded. Please try again later.', { status: 429 });
      }
      
    } catch (error) {
      console.error("Vercel Shield: Could not connect to KV store for rate limiting.", error);
    }
  }
  
  return NextResponse.next();
}

// this tells the middleware to only run on every request
export const config = {
  matcher: '/((?!_next/static|_next/image|favicon.ico).*)',
};
