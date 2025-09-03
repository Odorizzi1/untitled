// server.ts
import 'dotenv/config';
import express from 'express';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import ngrok from 'ngrok';
import * as crypto from 'node:crypto';

/**
 * Requer Node 18+ (fetch nativo).
 */

interface TokenResponse {
    access_token: string;
    token_type?: string;
    expires_in?: number;
}
interface DebugTokenResponse {
    data?: {
        app_id?: string;
        type?: string;
        application?: string;
        expires_at?: number;
        is_valid?: boolean;
        scopes?: string[];
        user_id?: string;
    };
    error?: { message: string; type: string; code: number; fbtrace_id?: string };
}
interface MeResponse {
    id?: string;
    name?: string;
    error?: { message: string; type: string; code: number; error_subcode?: number };
}
interface BusinessesResponse {
    data?: Array<{
        id: string;
        name: string;
        owned_whatsapp_business_accounts?: {
            data?: Array<{
                id: string;
                name: string;
                phone_numbers?: { data?: Array<{ id: string; display_phone_number: string }> };
            }>;
        };
    }>;
    error?: { message: string; type: string; code: number; error_subcode?: number };
}

const {
    META_APP_ID,
    META_APP_SECRET,
    META_API_VERSION = 'v20.0',
    CONFIG_ID,                   // obrigatório para Embedded Signup (mode=es)
    PORT = '3000',
    USE_NGROK = 'true',
    NGROK_AUTHTOKEN,
    PUBLIC_URL: PUBLIC_URL_ENV,  // opcional; se vazio, usa ngrok
    // opcionais para facilitar teste de envio:
    WABA_PERMANENT_TOKEN,        // token de Usuário de Sistema com whatsapp_business_messaging
    DEFAULT_PHONE_NUMBER_ID,     // phone_number_id do número do cliente
} = process.env as Record<string, string | undefined>;

if (!META_APP_ID || !META_APP_SECRET) {
    console.error('❌ Preencha .env: META_APP_ID e META_APP_SECRET');
    process.exit(1);
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let PUBLIC_URL = PUBLIC_URL_ENV || '';

const app = express();
app.use(express.json());

// === servir a pasta public e enviar o index ===
const PUBLIC_DIR = fs.existsSync(path.join(__dirname, 'public'))
    ? path.join(__dirname, 'public')
    : path.join(__dirname, '..', 'public');

app.use(express.static(PUBLIC_DIR));

app.get('/', (_req, res) => {
    const indexPath = path.join(PUBLIC_DIR, 'index.html');
    if (fs.existsSync(indexPath)) return res.sendFile(indexPath);

    res.type('html').send(`
    <h1>Meta OAuth / WhatsApp Embedded Signup</h1>
    <ul>
      <li><a href="/connect?mode=es">Embedded Signup (com config_id)</a></li>
      <li><a href="/connect?mode=login">Login puro (sem config_id)</a></li>
      <li><a href="/try-send">Teste de envio (WhatsApp Cloud API)</a></li>
    </ul>
    <p>Tenant opcional: acrescente <code>?tenantId=meu-tenant</code> no /connect.</p>
  `);
});

/**
 * Inicia o fluxo:
 *  - /connect?mode=es     -> Embedded Signup (usa CONFIG_ID)
 *  - /connect?mode=login  -> Login puro (sem CONFIG_ID)
 */
app.get('/connect', (req, res) => {
    const tenantId = typeof req.query.tenantId === 'string' ? req.query.tenantId : 'tenant-unknown';
    const mode = (typeof req.query.mode === 'string' ? req.query.mode : 'es').toLowerCase();

    if (!PUBLIC_URL) {
        return res
            .status(500)
            .send('PUBLIC_URL não definido. Suba com ngrok (USE_NGROK=true) ou defina PUBLIC_URL no .env');
    }

    const redirectUri = `${PUBLIC_URL}/integrations/meta/whatsapp/callback`;

    const statePayload = { tenantId, csrf: crypto.randomBytes(8).toString('hex'), mode };
    const state = encodeURIComponent(Buffer.from(JSON.stringify(statePayload)).toString('base64'));

    let url =
        `https://www.facebook.com/${META_API_VERSION}/dialog/oauth` +
        `?client_id=${encodeURIComponent(META_APP_ID!)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&state=${state}`;

    if (mode === 'es') {
        if (!CONFIG_ID) {
            return res.status(400).send('CONFIG_ID ausente. Defina CONFIG_ID no .env para usar Embedded Signup.');
        }
        url += `&config_id=${encodeURIComponent(CONFIG_ID)}`;
    }

    console.log(`➡️  /connect (${mode}) ->`, url);
    return res.redirect(url);
});

// === CALLBACK OAUTH (Redirect URI) ===
app.get('/integrations/meta/whatsapp/callback', async (req, res) => {
    try {
        // Se o Facebook mandou erro, mostre-o claro
        if (typeof req.query.error === 'string') {
            const details = {
                error: req.query.error,
                error_reason: req.query.error_reason,
                error_description: req.query.error_description,
            };
            return res.status(400).type('html').send(`
        <h2>❌ OAuth Error recebido do Facebook</h2>
        <pre>${JSON.stringify(details, null, 2)}</pre>
        <p>Verifique a <b>Valid OAuth Redirect URI</b> e o domínio em <b>Configurações → Básico</b>.</p>
      `);
        }

        const code = typeof req.query.code === 'string' ? req.query.code : undefined;
        const stateParam = typeof req.query.state === 'string' ? req.query.state : undefined;
        if (!code) return res.status(400).send('Faltou ?code na URL.');

        let mode = 'es';
        let stateDecoded: any = {};
        try {
            if (stateParam) {
                stateDecoded = JSON.parse(Buffer.from(decodeURIComponent(stateParam), 'base64').toString('utf8'));
                if (stateDecoded?.mode) mode = String(stateDecoded.mode);
            }
        } catch {}

        if (!PUBLIC_URL) return res.status(500).send('PUBLIC_URL não definido no callback.');
        const redirectUri = `${PUBLIC_URL}/integrations/meta/whatsapp/callback`;

        // Troca code -> access_token
        const tokenUrl =
            `https://graph.facebook.com/${META_API_VERSION}/oauth/access_token` +
            `?client_id=${encodeURIComponent(META_APP_ID!)}` +
            `&client_secret=${encodeURIComponent(META_APP_SECRET!)}` +
            `&redirect_uri=${encodeURIComponent(redirectUri)}` +
            `&code=${encodeURIComponent(code)}`;

        const tokenResp = await fetch(tokenUrl);
        const tokenJson = (await tokenResp.json()) as TokenResponse | any;

        if (!tokenResp.ok || !(tokenJson as TokenResponse).access_token) {
            console.error('Token error payload:', tokenJson);
            return res.status(400).send(`<pre>Falha ao obter access_token:\n${JSON.stringify(tokenJson, null, 2)}</pre>`);
        }
        const accessToken = (tokenJson as TokenResponse).access_token;

        // DEBUG_TOKEN: valida token e lê scopes
        const appToken = `${META_APP_ID}|${META_APP_SECRET}`;
        const debugUrl =
            `https://graph.facebook.com/${META_API_VERSION}/debug_token` +
            `?input_token=${encodeURIComponent(accessToken)}` +
            `&access_token=${encodeURIComponent(appToken)}`;
        const debugResp = await fetch(debugUrl);
        const debugJson = (await debugResp.json()) as DebugTokenResponse;

        const isValid = !!debugJson?.data?.is_valid;
        const matchesApp = debugJson?.data?.app_id === META_APP_ID;
        const expiresAt = debugJson?.data?.expires_at ? new Date(debugJson.data.expires_at * 1000).toISOString() : 'desconhecido';
        const tokenType = debugJson?.data?.type || 'desconhecido';
        const scopes: string[] = Array.isArray(debugJson?.data?.scopes) ? debugJson.data!.scopes! : [];
        const hasBM = scopes.includes('business_management');

        // /me: garante que o token acessa a Graph API
        const meResp = await fetch(
            `https://graph.facebook.com/${META_API_VERSION}/me?fields=id,name`,
            { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        const meJson = (await meResp.json()) as MeResponse;

        // /me/businesses: só chama se tiver business_management
        let bizBlock: string;
        if (hasBM) {
            const bizResp = await fetch(
                `https://graph.facebook.com/${META_API_VERSION}/me/businesses` +
                `?fields=id,name,owned_whatsapp_business_accounts{id,name,phone_numbers{id,display_phone_number}}`,
                { headers: { Authorization: `Bearer ${accessToken}` } }
            );
            const bizJson = (await bizResp.json()) as BusinessesResponse;
            bizBlock = `<h3>/me/businesses</h3><pre>${JSON.stringify(bizJson, null, 2)}</pre>`;
        } else {
            bizBlock = `<h3>/me/businesses</h3><pre>{"skipped": true, "reason": "missing business_management scope"}</pre>`;
        }

        const authOk = isValid && matchesApp && meResp.ok;

        res.status(authOk ? 200 : 400).type('html').send(`
      <h2>${authOk ? '✅ Autenticação válida' : '❌ Autenticação inválida'}</h2>
      <p><b>Modo:</b> ${mode === 'login' ? 'Login puro (sem config_id)' : 'Embedded Signup (com config_id)'}</p>
      <p><b>Redirect URI usada:</b> ${redirectUri}</p>

      <h3>Debug do Token</h3>
      <ul>
        <li><b>is_valid:</b> ${String(isValid)}</li>
        <li><b>app_id confere:</b> ${String(matchesApp)}</li>
        <li><b>tipo:</b> ${tokenType}</li>
        <li><b>expira em:</b> ${expiresAt}</li>
        <li><b>scopes:</b> ${scopes.join(', ') || '(vazio)'}</li>
        <li><b>business_management?</b> ${hasBM}</li>
      </ul>

      <h3>/me</h3>
      <pre>${JSON.stringify(meJson, null, 2)}</pre>

      ${bizBlock}

      <h3>Token (parcial)</h3>
      <pre>${accessToken.slice(0, 20)}... (não exponha em produção)</pre>

      <hr/>
      <p>Para testar envio, abra <a href="/try-send">/try-send</a>.</p>
    `);
    } catch (e) {
        console.error(e);
        res.status(500).send('Erro no callback.');
    }
});

/** Página simples para enviar mensagem usando token + phone_number_id **/
app.get('/try-send', (_req, res) => {
    res.type('html').send(`
    <h2>Teste de envio (WhatsApp Cloud API)</h2>
    <form id="f" onsubmit="send(event)">
      <label>phone_number_id <input name="phone_number_id" value="${DEFAULT_PHONE_NUMBER_ID ?? ''}" required/></label><br/>
      <label>Token (WABA permanent) <input name="token" value="${WABA_PERMANENT_TOKEN ?? ''}" required/></label><br/>
      <label>Para (E.164) <input name="to" placeholder="55XXXXXXXXXXX" required/></label><br/>
      <label>Texto <input name="text" value="Olá! Teste OK."/></label><br/>
      <button type="submit">Enviar texto</button>
    </form>
    <pre id="out"></pre>
    <script>
      async function send(ev){
        ev.preventDefault();
        const fd = new FormData(document.getElementById('f'));
        const payload = {
          phone_number_id: fd.get('phone_number_id'),
          token: fd.get('token'),
          to: fd.get('to'),
          text: fd.get('text') || 'Olá!'
        };
        const r = await fetch('/whatsapp/send-text', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const j = await r.json();
        document.getElementById('out').textContent = JSON.stringify(j, null, 2);
      }
    </script>
  `);
});

/** Endpoint de envio de texto **/
app.post('/whatsapp/send-text', async (req, res) => {
    try {
        const { phone_number_id, to, text, token } = req.body || {};
        if (!phone_number_id || !to || !token) {
            return res.status(400).json({ error: 'Informe phone_number_id, to e token' });
        }

        const resp = await fetch(
            `https://graph.facebook.com/${META_API_VERSION}/${encodeURIComponent(phone_number_id)}/messages`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    messaging_product: 'whatsapp',
                    to,
                    type: 'text',
                    text: { body: text || 'Olá!' }
                })
            }
        );
        const json = await resp.json();
        return res.status(resp.ok ? 200 : 400).json(json);
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: 'Falha ao enviar mensagem' });
    }
});

// healthcheck
app.get('/health', (_req, res) => res.send('ok'));

// === start ===
app.listen(Number(PORT), async () => {
    console.log(`🚀 Server on http://localhost:${PORT}`);

    if (USE_NGROK === 'true') {
        try {
            if (NGROK_AUTHTOKEN) await ngrok.authtoken(NGROK_AUTHTOKEN);
            PUBLIC_URL = await ngrok.connect({ addr: Number(PORT), proto: 'http' });
            console.log(`🌐 ngrok: ${PUBLIC_URL}`);
            console.log('👉 Redirect URI (cole no painel da Meta):');
            console.log(`   ${PUBLIC_URL}/integrations/meta/whatsapp/callback`);
            console.log('Abra a página de teste:', `${PUBLIC_URL}/`);
        } catch (e) {
            console.error('Erro ao abrir ngrok:', e);
            if (!PUBLIC_URL) console.log('Defina PUBLIC_URL no .env se não for usar ngrok.');
        }
    } else {
        if (!PUBLIC_URL) {
            console.warn('ℹ️ USE_NGROK=false, mas PUBLIC_URL não definido. Defina PUBLIC_URL no .env.');
        } else {
            console.log('PUBLIC_URL:', PUBLIC_URL);
            console.log(`Redirect URI: ${PUBLIC_URL}/integrations/meta/whatsapp/callback`);
        }
    }
});
