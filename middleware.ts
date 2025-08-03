// middleware.ts -> The Vercel Shield: A Production-Ready Firewall
// This middleware provides a robust, layered defense against automated abuse
// and the rate-limit bypass vulnerability.

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { kv } from '@vercel/kv';

// --- MAIN CONFIGURATION ---
// Tweak these settings to protect your application.
const FIREWALL_CONFIG = {
  
  // A smart rate limit for all untrusted public traffic.
  ipRateLimit: {
    // How many requests are allowed...
    limit: 30,
    // ...in this time window (in seconds).
    window: 20, 
  },

  // A list of secret tokens for your trusted services.
  // Any request with 'Authorization: Bearer <token>' where the token is in this list
  // will be considered TRUSTED and will BYPASS the IP rate limit.
  // Generate these with a password manager and keep them secret.
  trustedSecrets: [
    'k$tF_8#Z!pQvY7@eR_wJ6x*uG9hL4m&', // Secret for my own Cloudflare Worker
    's3C!bN_9^zP_qR$tW*vXyZ_2&4@6*8(0', // Secret for Stripe Webhooks
  ],

  // An array of paths to exclude from all firewall protections.
  // Example: ['/', '/about']
  // Leave empty to protect all paths.
  allowedPaths: [] as string[], 

};
// --- END OF CONFIGURATION ---

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  
  // 1. First, check if the path is globally allowed.
  if (FIREWALL_CONFIG.allowedPaths.includes(pathname)) {
    return NextResponse.next();
  }

  // 2. Next, check for a valid trusted secret (the "VIP Pass").
  const authHeader = req.headers.get('Authorization') ?? '';
  const token = authHeader.replace('Bearer ', '');
  if (FIREWALL_CONFIG.trustedSecrets.includes(token)) {
    // This is a trusted service. Let it pass without checking the IP rate limit.
    return NextResponse.next();
  }

  // 3. If it's not a trusted service, treat it as public traffic and enforce the IP rate limit.
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
    // If the KV store is down, it's safer to let traffic through.
    console.error("Vercel Shield: KV store error.", error);
  }
  
  // 4. If all checks pass, allow the request.
  return NextResponse.next();
}

// this tells the middleware to run on every request except for static files.
export const config = {
  matcher: '/((?!_next/static|_next/image|favicon.ico).*)',
};