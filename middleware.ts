// middleware.ts -> The Vercel Shield: A Production-Ready Firewall
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { kv } from '@vercel/kv';

// --- MAIN CONFIGURATION ---
// Tweak these settings to protect your application.
const FIREWALL_CONFIG = {
  
  // A smart rate limit for all untrusted public traffic.
  ipRateLimit: {
    limit: 30,
    window: 20, // in seconds
  },

  // A list of secret tokens for your trusted services.
  // Any request with 'Authorization: Bearer <token>' where the token is in this list
  // will be considered TRUSTED and will BYPASS the IP rate limit.
  trustedSecrets: [
    'k$tF_8#Z!pQvY7@eR_wJ6x*uG9hL4m&', // Secret for your own worker
    's3C!bN_9^zP_qR$tW*vXyZ_2&4@6*8(0', // Secret for a trusted webhook
  ],

  // An array of paths to exclude from all firewall protections.
  allowedPaths: [] as string[], 

};
// --- END OF CONFIGURATION ---

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  
  // 1. First, check if the path is globally allowed.
  if (FIREWALL_CONFIG.allowedPaths.includes(pathname)) {
    return NextResponse.next();
  }

  // --- THE CRITICAL NEW LOGIC IS HERE ---
  // 2. Check if the request is coming from a Cloudflare Worker.
  const isWorkerRequest = req.headers.has('cf-worker');

  // 3. Check for a valid trusted secret (the "VIP Pass").
  const authHeader = req.headers.get('Authorization') ?? '';
  const token = authHeader.replace('Bearer ', '');
  const hasValidSecret = FIREWALL_CONFIG.trustedSecrets.includes(token) && token !== '';

  // 4. Enforce the new security policy.
  if (isWorkerRequest) {
    if (hasValidSecret) {
      // It's a worker, but it has our secret. Let it pass without an IP limit.
      return NextResponse.next();
    } else {
      // It's a worker, and it DOES NOT have our secret. Block it immediately.
      return new NextResponse('Forbidden: Untrusted worker access is not permitted.', { status: 403 });
    }
  }
  // --- END OF NEW LOGIC ---

  // 5. If it's not a worker request, treat it as normal public traffic and enforce the IP rate limit.
  const ip = req.headers.get('cf-connecting-ip') ?? req.headers.get('x-forwarded-for') ?? '127.0.0.1';
  const key = `ratelimit:${ip}`;

  try {
    const currentRequests = await kv.incr(key);
    if (currentRequests === 1) {
      await kv.expire(key, FIREWALL_CONFIG.ipRateLimit.window);
    }
    if (currentRequests > FIREWALL_CONFIG.ipRateLimit.limit) {
      return new NextResponse('Rate limit exceeded.', { status: 429 });
    }
  } catch (error) {
    console.error("Vercel Shield: KV store error.", error);
  }
  
  // 6. If all checks pass, allow the request.
  return NextResponse.next();
}

// this tells the middleware to run on every request except for static files.
export const config = {
  matcher: '/((?!_next/static|_next/image|favicon.ico).*)',
};