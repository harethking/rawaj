// Al-Waseet delivery integration for Rawaj stores.
// Store owners connect their own Al-Waseet merchant account, send orders to it and track them.
// Customers can see the live delivery status of their own order (public_track).
// Merchant passwords are AES-GCM encrypted at rest and never returned to the browser.
import { createClient, type SupabaseClient } from 'npm:@supabase/supabase-js@2';

const API = 'https://api.alwaseet-iq.net/v1/merchant';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

function secretKey(): string {
  const keys = Deno.env.get('SUPABASE_SECRET_KEYS');
  if (keys) { try { const k = JSON.parse(keys)['default']; if (k) return k; } catch (_) { /* fall back */ } }
  return Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
}

/* ---------- encryption of the merchant password ---------- */
const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
let keyP: Promise<CryptoKey> | null = null;
function aesKey() {
  if (!keyP) {
    const secret = Deno.env.get('WASEET_ENC_KEY') || secretKey();
    keyP = crypto.subtle.digest('SHA-256', new TextEncoder().encode('rawaj-waseet:' + secret))
      .then((h) => crypto.subtle.importKey('raw', h, 'AES-GCM', false, ['encrypt', 'decrypt']));
  }
  return keyP;
}
async function encrypt(text: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(), new TextEncoder().encode(text)));
  return b64(iv) + '.' + b64(ct);
}
async function decrypt(s: string) {
  const [iv, ct] = s.split('.');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await aesKey(), unb64(ct));
  return new TextDecoder().decode(pt);
}

/* ---------- Al-Waseet API ---------- */
type WsResp = { status?: boolean; errNum?: string; msg?: string; data?: any };

async function wsFetch(path: string, opts: { token?: string; form?: Record<string, string | number>; query?: Record<string, string | number> } = {}): Promise<WsResp> {
  const u = new URL(API + path);
  if (opts.token) u.searchParams.set('token', opts.token);
  for (const [k, v] of Object.entries(opts.query || {})) u.searchParams.set(k, String(v));
  const init: RequestInit = { method: 'GET' };
  if (opts.form) {
    const fd = new FormData();
    for (const [k, v] of Object.entries(opts.form)) fd.append(k, String(v));
    init.method = 'POST';
    init.body = fd;
  }
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 20000);
  try {
    const r = await fetch(u, { ...init, signal: ctl.signal });
    const j = await r.json().catch(() => null);
    if (!j || typeof j !== 'object') return { status: false, errNum: 'UPSTREAM', msg: `HTTP ${r.status}` };
    return j as WsResp;
  } catch (_) {
    return { status: false, errNum: 'UPSTREAM', msg: 'تعذّر الاتصال بشركة الوسيط' };
  } finally {
    clearTimeout(timer);
  }
}

async function wsLogin(username: string, password: string) {
  const j = await wsFetch('/login', { form: { username, password } });
  if (!j.status || !j.data?.token) return { ok: false as const, msg: j.msg || 'فشل تسجيل الدخول' };
  return { ok: true as const, token: String(j.data.token) };
}

type Account = { store_id: string; username: string; password: string; token: string | null };

async function loadAccount(db: SupabaseClient, storeId: string): Promise<Account | null> {
  const { data } = await db.from('waseet_accounts').select('store_id,username,password_enc,token').eq('store_id', storeId).maybeSingle();
  if (!data) return null;
  try {
    return { store_id: data.store_id, username: data.username, password: await decrypt(data.password_enc), token: data.token };
  } catch (_) {
    return null; // key changed: the owner has to connect again
  }
}

// Calls the API with the saved token; on failure logs in again once (token expires on password change).
async function call(db: SupabaseClient, acc: Account, path: string, opts: { form?: Record<string, string | number>; query?: Record<string, string | number> } = {}): Promise<WsResp> {
  if (acc.token) {
    const j = await wsFetch(path, { ...opts, token: acc.token });
    if (j.status || j.errNum === 'UPSTREAM') return j;
  }
  const l = await wsLogin(acc.username, acc.password);
  if (!l.ok) return { status: false, errNum: 'LOGIN', msg: 'بيانات حساب الوسيط لم تعد صحيحة، اربط الحساب من جديد' };
  acc.token = l.token;
  await db.from('waseet_accounts').update({ token: l.token, updated_at: new Date().toISOString() }).eq('store_id', acc.store_id);
  return wsFetch(path, { ...opts, token: l.token });
}

const ID_RE = /^[0-9A-Za-z-]{1,30}$/;
function slimOrder(x: any) {
  return {
    id: x?.id != null ? String(x.id) : null,
    qr_id: x?.qr_id != null ? String(x.qr_id) : (x?.id != null ? String(x.id) : null),
    status: x?.status ?? null,
    status_id: x?.status_id ?? null,
    notes: x?.issue_notes ?? null,
    updated_at: x?.updated_at ?? null,
  };
}
const asList = (d: any) => (Array.isArray(d) ? d : d && typeof d === 'object' ? Object.values(d) : []);
const str = (v: unknown, max: number) => String(v ?? '').trim().slice(0, max);
const int = (v: unknown) => { const n = Number(v); return Number.isInteger(n) ? n : NaN; };
const normPhone = (p: unknown) => String(p || '').replace(/[\s-]/g, '').replace(/^\+964/, '0');

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ error: 'METHOD' }, 405);

  let body: Record<string, any>;
  try { body = await req.json(); } catch (_) { return json({ error: 'BAD_JSON' }, 400); }
  const action = String(body.action || '');
  const db = createClient(Deno.env.get('SUPABASE_URL')!, secretKey(), { auth: { persistSession: false } });

  /* ----- public: a customer checks the delivery status of their own order ----- */
  if (action === 'public_track') {
    const slug = str(body.slug, 40), no = int(body.no), phone = normPhone(body.phone);
    if (!slug || !Number.isInteger(no) || !/^07[0-9]{9}$/.test(phone)) return json({ error: 'BAD_INPUT' }, 400);
    const { data: st } = await db.from('stores').select('id,data').eq('slug', slug).maybeSingle();
    const orders = Array.isArray(st?.data?.orders) ? st!.data.orders : [];
    const o = orders.find((x: any) => String(x?.no) === String(no) && normPhone(x?.customer?.phone) === phone);
    const ref = o?.waseet?.qrId || o?.waseet?.id;
    if (!o || !ref) return json({ waseet: null });
    const acc = await loadAccount(db, st!.id);
    if (!acc) return json({ waseet: null });
    const j = await call(db, acc, '/get-orders-by-ids-bulk', { form: { ids: String(ref) } });
    const item = asList(j.data).map(slimOrder).find((x) => x.qr_id === String(ref) || x.id === String(ref));
    return json({ waseet: item ? { status: item.status, updated_at: item.updated_at } : null });
  }

  /* ----- everything else: the store owner (or the platform admin) ----- */
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token) return json({ error: 'UNAUTHENTICATED' }, 401);
  const { data: who, error: whoErr } = await db.auth.getUser(token);
  if (whoErr || !who?.user) return json({ error: 'UNAUTHENTICATED' }, 401);

  let storeId = '';
  if (body.store_id) {
    storeId = String(body.store_id);
    if (!/^[0-9a-f-]{36}$/i.test(storeId)) return json({ error: 'BAD_STORE' }, 400);
    const { data: st } = await db.from('stores').select('owner_id').eq('id', storeId).maybeSingle();
    if (!st) return json({ error: 'NO_STORE' }, 404);
    if (st.owner_id !== who.user.id) {
      const { data: prof } = await db.from('profiles').select('is_admin').eq('id', who.user.id).maybeSingle();
      if (!prof?.is_admin) return json({ error: 'FORBIDDEN' }, 403);
    }
  } else {
    const { data: st } = await db.from('stores').select('id').eq('owner_id', who.user.id).maybeSingle();
    if (!st) return json({ error: 'NO_STORE' }, 404);
    storeId = st.id;
  }

  if (action === 'connect') {
    const username = str(body.username, 100), password = String(body.password ?? '').slice(0, 200);
    if (!username || !password) return json({ ok: false, msg: 'اكتب اسم المستخدم وكلمة المرور' });
    const l = await wsLogin(username, password);
    if (!l.ok) return json({ ok: false, msg: l.msg === 'ok' ? 'فشل تسجيل الدخول' : l.msg });
    const { error } = await db.from('waseet_accounts').upsert({
      store_id: storeId, username, password_enc: await encrypt(password), token: l.token, updated_at: new Date().toISOString(),
    });
    if (error) return json({ ok: false, msg: 'تعذّر حفظ الربط' }, 500);
    return json({ ok: true, username });
  }

  if (action === 'disconnect') {
    await db.from('waseet_accounts').delete().eq('store_id', storeId);
    return json({ ok: true });
  }

  const acc = await loadAccount(db, storeId);
  if (action === 'status') return json({ connected: !!acc, username: acc?.username || null });
  if (!acc) return json({ ok: false, error: 'NOT_CONNECTED', msg: 'اربط حساب الوسيط من الإعدادات أولاً' });

  const pass = (j: WsResp) => (j.status ? json({ ok: true, data: j.data ?? null }) : json({ ok: false, msg: j.msg || 'رفضت شركة الوسيط الطلب' }));

  if (action === 'cities') return pass(await call(db, acc, '/citys'));
  if (action === 'sizes') return pass(await call(db, acc, '/package-sizes'));
  if (action === 'regions') {
    const cityId = int(body.city_id);
    if (!Number.isInteger(cityId)) return json({ ok: false, msg: 'اختر المحافظة' });
    return pass(await call(db, acc, '/regions', { query: { city_id: cityId } }));
  }

  if (action === 'create') {
    const o = body.order || {};
    const f = {
      client_name: str(o.client_name, 60),
      client_mobile: str(o.client_mobile, 20),
      client_mobile2: str(o.client_mobile2, 20),
      city_id: int(o.city_id),
      region_id: int(o.region_id),
      location: str(o.location, 250),
      type_name: str(o.type_name, 100),
      items_number: int(o.items_number),
      price: int(o.price),
      package_size: int(o.package_size),
      merchant_notes: str(o.merchant_notes, 300),
      replacement: int(o.replacement) === 1 ? 1 : 0,
    };
    const phoneRe = /^\+9647[0-9]{9}$/;
    if (f.client_name.length < 2) return json({ ok: false, msg: 'اسم الزبون قصير' });
    if (!phoneRe.test(f.client_mobile)) return json({ ok: false, msg: 'رقم الزبون غير صحيح' });
    if (f.client_mobile2 && !phoneRe.test(f.client_mobile2)) return json({ ok: false, msg: 'الرقم الثاني غير صحيح' });
    if (!Number.isInteger(f.city_id) || !Number.isInteger(f.region_id)) return json({ ok: false, msg: 'اختر المحافظة والمنطقة' });
    if (f.location.length < 3) return json({ ok: false, msg: 'اكتب العنوان' });
    if (!f.type_name) return json({ ok: false, msg: 'اكتب نوع البضاعة' });
    if (!Number.isInteger(f.items_number) || f.items_number < 1 || f.items_number > 999) return json({ ok: false, msg: 'عدد القطع غير صحيح' });
    if (!Number.isInteger(f.price) || f.price < 0 || f.price > 100000000) return json({ ok: false, msg: 'السعر غير صحيح' });
    if (!Number.isInteger(f.package_size)) return json({ ok: false, msg: 'اختر حجم الطرد' });
    const form: Record<string, string | number> = { ...f };
    if (!f.client_mobile2) delete form.client_mobile2;
    if (!f.merchant_notes) delete form.merchant_notes;
    const j = await call(db, acc, '/create-order', { form });
    if (!j.status) return json({ ok: false, msg: j.msg || 'رفضت شركة الوسيط الطلب' });
    const d = Array.isArray(j.data) ? j.data[0] : j.data;
    return json({ ok: true, order: { id: d?.id != null ? String(d.id) : null, qr_id: d?.qr_id != null ? String(d.qr_id) : null, qr_link: d?.qr_link || null, status: d?.status || null } });
  }

  if (action === 'track') {
    const ids = (Array.isArray(body.ids) ? body.ids : []).map(String).filter((x: string) => ID_RE.test(x)).slice(0, 25);
    if (!ids.length) return json({ ok: true, data: [] });
    const j = await call(db, acc, '/get-orders-by-ids-bulk', { form: { ids: ids.join(',') } });
    if (!j.status) return json({ ok: false, msg: j.msg || 'تعذّر جلب الحالات' });
    return json({ ok: true, data: asList(j.data).map(slimOrder) });
  }

  return json({ error: 'BAD_ACTION' }, 400);
});
