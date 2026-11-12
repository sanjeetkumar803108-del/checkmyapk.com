import DodoPayments from 'dodopayments';
import type { AccountPlan } from '../../src/types/account';

export type PaidAccountPlan = Exclude<AccountPlan, 'free'>;
export type BillingCycle = 'monthly' | 'annual';

export class BillingConfigError extends Error {
  statusCode: number;
  constructor(message: string, statusCode = 503) {
    super(message);
    this.name = 'BillingConfigError';
    this.statusCode = statusCode;
  }
}

function getDodoEnvironment(): 'live_mode' | 'test_mode' {
  const raw = String(process.env.DODO_ENV || 'test_mode').trim().toLowerCase();
  if (raw === 'live' || raw === 'live_mode' || raw === 'production') {
    return 'live_mode';
  }
  return 'test_mode';
}

function getProductIdMap(): Record<PaidAccountPlan, Record<BillingCycle, string>> {
  return {
    pro: {
      monthly: String(process.env.DODO_PRODUCT_PRO_MONTHLY || '').trim(),
      annual: String(process.env.DODO_PRODUCT_PRO_ANNUAL || '').trim(),
    },
    agency: {
      monthly: String(process.env.DODO_PRODUCT_AGENCY_MONTHLY || '').trim(),
      annual: String(process.env.DODO_PRODUCT_AGENCY_ANNUAL || '').trim(),
    },
  };
}

function createDodoClient(): DodoPayments {
  const bearerToken = String(process.env.DODO_PAYMENTS_API_KEY || '').trim();
  if (!bearerToken) {
    throw new BillingConfigError(
      'Dodo Payments checkout is awaiting live API credentials. Please contact support or try again shortly.',
      503
    );
  }
  const webhookKey = String(process.env.DODO_PAYMENTS_WEBHOOK_KEY || '').trim() || undefined;
  return new DodoPayments({
    bearerToken,
    webhookKey,
    environment: getDodoEnvironment(),
  });
}

export function getDodoBillingStatus() {
  const apiKeyConfigured = Boolean(String(process.env.DODO_PAYMENTS_API_KEY || '').trim());
  const webhookConfigured = Boolean(String(process.env.DODO_PAYMENTS_WEBHOOK_KEY || '').trim());
  const products = getProductIdMap();

  return {
    provider: 'dodo' as const,
    environment: getDodoEnvironment(),
    configured:
      apiKeyConfigured &&
      Boolean(products.pro.monthly || products.pro.annual || products.agency.monthly || products.agency.annual),
    webhookConfigured,
    products: {
      pro: {
        monthly: Boolean(products.pro.monthly),
        annual: Boolean(products.pro.annual),
      },
      agency: {
        monthly: Boolean(products.agency.monthly),
        annual: Boolean(products.agency.annual),
      },
    },
  };
}

export function resolvePlanFromProductId(
  productId?: string | null
): { plan: PaidAccountPlan; billingCycle: BillingCycle } | null {
  const target = String(productId || '').trim();
  if (!target) return null;
  const products = getProductIdMap();
  for (const plan of ['pro', 'agency'] as const) {
    for (const cycle of ['monthly', 'annual'] as const) {
      if (products[plan][cycle] && products[plan][cycle] === target) {
        return { plan, billingCycle: cycle };
      }
    }
  }
  return null;
}

export async function createDodoCheckoutSession(input: {
  userId: string;
  email: string;
  name: string;
  plan: PaidAccountPlan;
  billingCycle: BillingCycle;
  originUrl?: string;
}): Promise<{ checkoutUrl: string; sessionId: string }> {
  const products = getProductIdMap();
  const productId = products[input.plan]?.[input.billingCycle];
  if (!productId) {
    throw new BillingConfigError(
      `Checkout for ${input.plan.toUpperCase()} (${input.billingCycle}) is not configured yet. Please add the Dodo product ID or contact support.`,
      503
    );
  }

  const client = createDodoClient();
  const baseUrl = String(process.env.PUBLIC_APP_URL || input.originUrl || 'https://checkmyapk.com')
    .trim()
    .replace(/\/+$/, '');

  const returnUrl = `${baseUrl}/?page=account&checkout=success&plan=${encodeURIComponent(
    input.plan
  )}&cycle=${encodeURIComponent(input.billingCycle)}`;

  const session = await client.checkoutSessions.create({
    product_cart: [{ product_id: productId, quantity: 1 }],
    customer: {
      email: input.email,
      name: input.name || input.email.split('@')[0],
    },
    return_url: returnUrl,
    metadata: {
      userId: input.userId,
      plan: input.plan,
      billingCycle: input.billingCycle,
      source: 'checkmyapk-web',
    },
  });

  if (!session.checkout_url) {
    throw new BillingConfigError('Dodo Payments did not return a hosted checkout URL.', 502);
  }

  return {
    checkoutUrl: session.checkout_url,
    sessionId: session.session_id,
  };
}

export type VerifiedDodoWebhookEvent = ReturnType<DodoPayments['webhooks']['unwrap']>;

export function unwrapDodoWebhook(
  rawBody: string,
  incomingHeaders: Record<string, string | string[] | undefined>
): VerifiedDodoWebhookEvent {
  const webhookKey = String(process.env.DODO_PAYMENTS_WEBHOOK_KEY || '').trim();
  if (!webhookKey) {
    throw new BillingConfigError('Dodo webhook signing secret is not configured.', 503);
  }

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(incomingHeaders)) {
    if (typeof v === 'string') {
      headers[k.toLowerCase()] = v;
    } else if (Array.isArray(v) && v.length > 0) {
      headers[k.toLowerCase()] = String(v[0]);
    }
  }

  // Instantiate lightweight client for signature verification even if API key is unset in isolated tests.
  const client = new DodoPayments({
    bearerToken: String(process.env.DODO_PAYMENTS_API_KEY || 'webhook-verify-only').trim(),
    webhookKey,
    environment: getDodoEnvironment(),
  });

  return client.webhooks.unwrap(rawBody, {
    headers,
    key: webhookKey,
  });
}

