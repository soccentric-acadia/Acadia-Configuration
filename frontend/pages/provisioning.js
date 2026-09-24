// First-use provisioning (P-A10): HQ trust material and the IV&V client.
// The device never shows the material back — only whether it is present,
// where it came from (device / image) and a short SHA-256 fingerprint.

import { el } from '../core/dom.js';
import { Card } from '../components/card.js';
import { Field } from '../components/field.js';
import { Button } from '../components/button.js';
import { ActionList, ActionRow } from '../components/action-row.js';

function status(item) {
    if (!item || !item.provisioned) return 'Not provisioned';
    if (!item.sha256_prefix) return `Provisioned (${item.source})`;
    return `Provisioned (${item.source}, sha256 ${item.sha256_prefix}…)`;
}

export async function render(api, store) {
    const state = await api.get('/api/v1/provisioning');

    const ca = Field({ label: 'HQ CA certificate (PEM)', type: 'textarea', placeholder: '-----BEGIN CERTIFICATE-----', help: `The CA that issued the HQ gateway certificate. ${status(state.hq_ca)}.` });
    const key = Field({ label: 'HQ configuration-signing key (PEM or base64)', type: 'textarea', placeholder: '-----BEGIN PUBLIC KEY-----', help: `Ed25519 public key HQ signs configuration writes with. ${status(state.hq_config_key)}.` });
    const hqCard = Card({
        title: 'HQ trust',
        subtitle: 'Required before this device accepts HQ configuration or connects to HQ over TLS.',
        footer: ActionList(ActionRow('Save HQ trust', 'Store the provided material on the persistent store (kept across updates).', Button({
            onClick: async () => {
                const body = {};
                if (ca.get().trim()) body.hq_ca_pem = ca.get();
                if (key.get().trim()) body.hq_config_pubkey_pem = key.get();
                if (!Object.keys(body).length) { store.toast('Paste a certificate or key first', 'error'); return; }
                await api.put('/api/v1/provisioning/hq-trust', body);
                store.toast('HQ trust saved', 'success');
            },
        }, 'Save'))),
    }, el('div', { class: 'stack' }, ca.wrap, key.wrap));

    const ivv = state.ivv_client || {};
    const addr = Field({ label: 'IV&V server address', value: ivv.server_address || '', placeholder: '192.168.1.100', help: 'Host name or IP of the Acadia-Server this device streams test results to.' });
    const port = Field({ label: 'Port', type: 'number', value: ivv.server_port || 50051 });
    const token = Field({ label: 'Stream token', type: 'password', help: ivv.stream_token_set ? 'A token is set; leave empty to clear it.' : 'Must match the server’s ACADIA_STREAM_TOKEN when it requires one.' });
    const tlsCa = Field({ label: 'Server CA (PEM, optional)', type: 'textarea', help: ivv.tls ? 'TLS is configured.' : 'Leave empty for a plaintext lab subnet.' });
    const ivvCard = Card({
        title: 'IV&V client',
        subtitle: 'Where acadia-client connects. The client starts once this is provisioned.',
        footer: ActionList(ActionRow('Save and restart the client', 'Write the client configuration and restart acadia-client.', Button({
            onClick: async () => {
                const res = await api.put('/api/v1/provisioning/ivv-client', {
                    server_address: addr.get().trim(),
                    server_port: Number(port.get()) || 50051,
                    server_stream_token: token.get() || null,
                    tls_ca_pem: tlsCa.get().trim() || null,
                });
                store.toast(res.restarted ? 'IV&V client provisioned and restarted' : 'Saved; the client did not restart — check Services', res.restarted ? 'success' : 'error');
            },
        }, 'Save'))),
    }, el('div', { class: 'form-grid' }, addr.wrap, port.wrap, token.wrap, tlsCa.wrap));

    return el('div', {},
        el('div', { class: 'page-header' },
            el('h1', {}, 'Provisioning'),
            el('p', {}, 'First-use setup: HQ trust material and the IV&V server connection.')),
        hqCard, ivvCard);
}
