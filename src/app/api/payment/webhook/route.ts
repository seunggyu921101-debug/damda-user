import { NextRequest } from "next/server";
import { createServiceClient } from "@/lib/supabase/service";
import { paymentConfig, verifyGatewaySignature } from "@/lib/payments/nicepay";
import { reconcilePayment } from "@/lib/payments/finalize";
import { forwardRefundWebhook } from "@/lib/payments/refund-webhook";

const webhookHeaders = { "Content-Type": "text/html", "Cache-Control": "no-store" };

function webhookOk() {
  return new Response("OK", { status: 200, headers: webhookHeaders });
}

function isRegistrationProbe(body: unknown) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return false;
  // A delivery that can change payment state must include at least one of
  // these signed-event fields. NICEPAY's endpoint registration probe does not.
  return !["tid", "orderId", "amount", "ediDate", "signature"].some((key) => key in body);
}

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text();
    // NICEPAY sends a non-event request while validating a newly registered
    // endpoint. It carries no transaction data and is deliberately handled
    // before configuration/signature validation. Every event-shaped payload
    // continues through the strict signature and order verification below.
    if (!rawBody.trim()) return webhookOk();
    let body: unknown;
    try {
      body = JSON.parse(rawBody);
    } catch {
      // NICEPAY documents JSON for deliveries. A non-JSON registration probe
      // cannot affect state, while a real event will still be reconciled by
      // the independently verified batch job if delivery is malformed.
      return webhookOk();
    }
    if (isRegistrationProbe(body)) return webhookOk();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return new Response("Rejected", { status: 400 });
    }
    const payload = body as Record<string, unknown>;
    // NICEPAY validates a new URL by sending a sample notification whose
    // orderId is not one of this merchant's orders. Acknowledging an unknown
    // order cannot change any state. Known orders remain signature-verified.
    if (typeof payload.orderId !== "string") return webhookOk();
    const service = createServiceClient();
    const { data: order, error } = await service.from("payment_orders").select("*").eq("order_id", payload.orderId).maybeSingle();
    if (error) return new Response("Review pending", { status: 503, headers: webhookHeaders });
    if (!order) return webhookOk();
    const config = paymentConfig();
    verifyGatewaySignature(payload, config);
    if (payload.status === "cancelled" || payload.status === "partialCancelled") {
      return await forwardRefundWebhook(payload);
    }
    if (payload.amount !== order.amount) return new Response("Rejected", { status: 400 });
    const result = await reconcilePayment({ order, tid: payload.tid as string, actorId: null, source: "webhook",
      config, rpc: (name, args) => service.rpc(name, args), allowApproval: false });
    return result.success
      ? webhookOk()
      : new Response("Review pending", { status: 503, headers: webhookHeaders });
  } catch { return new Response("Rejected", { status: 400 }); }
}
