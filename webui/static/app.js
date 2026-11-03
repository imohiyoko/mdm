// MDM の管理画面。管理の API（/v1/）をクッキーのセッションで呼ぶ。
// 画面に出す値はすべて textContent で入れる（HTML として解釈しない）。
"use strict";

const state = { me: null, orgs: [], org: null, tab: "overview" };

// --- 小さな道具

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function say(text, kind) {
  const box = document.getElementById("msg");
  box.replaceChildren(h("div", { class: kind || "ok" }, text));
  if (kind !== "error") setTimeout(() => box.replaceChildren(), 4000);
}

class APIError extends Error {
  constructor(status, body) {
    super((body && (body.message || body.error)) || "エラー " + status);
    this.status = status;
  }
}

async function api(method, path, body) {
  const headers = { "X-MDM-UI": "1" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(path, { method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body) });
  const data = r.status === 204 ? null : await r.json().catch(() => null);
  if (r.status === 401) {
    renderLogin();
    throw new APIError(401, { message: "ログインしてください" });
  }
  if (!r.ok) throw new APIError(r.status, data);
  return data;
}

// run は API を呼ぶ操作を行い、失敗したら画面に出す。
async function run(fn, done) {
  try {
    await fn();
    if (done) say(done);
  } catch (e) {
    if (e.status !== 401) say(e.message, "error");
  }
}

function fmtTime(t) {
  if (!t) return "";
  const d = new Date(t);
  return isNaN(d) ? "" : d.toLocaleString("ja-JP");
}

function formData(form) {
  const out = {};
  for (const [k, v] of new FormData(form).entries()) {
    if (typeof v === "string" && v.trim() !== "") out[k] = v.trim();
  }
  return out;
}

function table(headers, rows) {
  return h("div", { class: "table" },
    h("table", null,
      h("thead", null, h("tr", null, headers.map((x) => h("th", null, x)))),
      h("tbody", null, rows.length ? rows : h("tr", null, h("td", { colspan: headers.length, class: "muted" }, "まだありません")))));
}

function canWrite() {
  const me = state.me;
  return me.roles.some((r) => r.role === "server_admin" || (r.role === "org_admin" && r.org_id === state.org.id));
}

function isServerAdmin() {
  return state.me.roles.some((r) => r.role === "server_admin");
}

// --- 画面

function renderLogin() {
  document.getElementById("who").replaceChildren();
  document.getElementById("app").replaceChildren(
    h("div", { class: "card" },
      h("h2", null, "ログイン"),
      h("p", null, "IAM のアカウントでログインします。"),
      h("button", { onclick: () => { location.href = "/ui/login"; } }, "IAM でログイン")));
}

function signupCard() {
  if (!state.me.can_signup) return null;
  return h("div", { class: "card" },
    h("h3", null, "新しい組織を作る"),
    h("p", { class: "muted" }, "作った人がその組織の管理者になります。"),
    h("form", {
      class: "row", onsubmit: (ev) => {
        ev.preventDefault();
        const body = formData(ev.target);
        run(async () => { const o = await api("POST", "/v1/signup", body); await boot(o.id); }, "組織を作りました");
      },
    },
      h("input", { name: "name", placeholder: "組織の名前（例 すずき家）", required: true, maxlength: 100 }),
      h("select", { name: "kind" }, h("option", { value: "family" }, "家族"), h("option", { value: "company" }, "会社")),
      h("button", null, "作る")));
}

function acceptCard() {
  return h("div", { class: "card" },
    h("h3", null, "招待を受ける"),
    h("p", { class: "muted" }, "ほかの管理者からもらった招待のコード（mdminv_ で始まる）を入れます。"),
    h("form", {
      class: "row", onsubmit: (ev) => {
        ev.preventDefault();
        const body = formData(ev.target);
        run(async () => { const b = await api("POST", "/v1/invitations/accept", body); await boot(b.org_id); }, "組織の管理者になりました");
      },
    },
      h("input", { name: "code", placeholder: "mdminv_…", required: true, autocomplete: "off" }),
      h("button", null, "受ける")));
}

function renderNoRole() {
  document.getElementById("app").replaceChildren(
    h("div", { class: "card" }, h("p", null, "まだどの組織の管理者でもありません。")),
    signupCard(), acceptCard());
}

const tabs = [
  ["overview", "概要"], ["devices", "端末"], ["people", "人"], ["groups", "グループ"],
  ["automations", "自動のルール"], ["admins", "管理者"], ["routers", "Wi-Fi のルーター"], ["audit", "操作の記録"],
];

function renderOrg() {
  const app = document.getElementById("app");
  const picker = h("select", {
    "aria-label": "組織", onchange: (ev) => { state.org = state.orgs.find((o) => o.id === ev.target.value); state.tab = "overview"; renderOrg(); },
  }, state.orgs.map((o) => h("option", { value: o.id, selected: o.id === state.org.id }, o.name)));
  const nav = h("nav", { class: "tabs" }, tabs.map(([key, label]) =>
    h("button", { "aria-current": state.tab === key ? "page" : null, onclick: () => { state.tab = key; renderOrg(); } }, label)));
  const body = h("section", null, h("p", { class: "muted" }, "読み込んでいます…"));
  app.replaceChildren(h("div", { class: "row" }, picker), nav, body);
  const view = { overview, devices, people, groups, automations, admins, routers, audit }[state.tab];
  run(async () => body.replaceChildren(...[await view()].flat()));
}

// --- 概要

async function overview() {
  const u = await api("GET", `/v1/orgs/${state.org.id}/usage`);
  const names = { devices: "端末", people: "人", groups: "グループ", policies: "ポリシー" };
  const rows = Object.entries(names).map(([k, label]) => {
    const used = u.usage[k], max = u.limits[k];
    const pct = max > 0 ? Math.min(100, Math.round((used / max) * 100)) : 0;
    return h("tr", null, h("td", null, label), h("td", null, max > 0 ? `${used} / ${max}` : `${used}（上限なし）`),
      h("td", null, max > 0 ? h("div", { class: "meter" }, h("span", { style: null, "data-pct": pct })) : ""));
  });
  const t = table(["", "使っている数", ""], rows);
  // CSP で style 属性を使わないため、幅は DOM の style で入れる。
  t.querySelectorAll(".meter > span").forEach((s) => { s.style.width = s.dataset.pct + "%"; });
  return [
    h("div", { class: "card" },
      h("h2", null, state.org.name),
      h("p", { class: "muted" }, state.org.kind === "company" ? "会社" : "家族", " · ", state.org.id),
      t,
      h("p", { class: "muted" }, `管理者 ${u.usage.admins} 人 · ルーター ${u.usage.radius_clients} 台 · IAM の受け手 ${u.usage.ssf_receivers}`)),
    signupCard(), acceptCard(),
  ];
}

// --- 端末

const platforms = { ios: "iPhone・iPad", macos: "Mac", android: "Android", windows: "Windows", other: "そのほか" };

async function devices() {
  const [ds, ps] = await Promise.all([api("GET", `/v1/devices?org_id=${state.org.id}`), api("GET", `/v1/people?org_id=${state.org.id}`)]);
  const person = Object.fromEntries(ps.people.map((p) => [p.id, p.name]));
  const out = h("div");
  const rows = ds.devices.map((d) => h("tr", null,
    h("td", null, d.name, h("div", { class: "muted" }, d.id)),
    h("td", null, platforms[d.platform] || d.platform),
    h("td", null, person[d.person_id] || ""),
    h("td", null, d.paused_until ? `止めている（${fmtTime(d.paused_until)} まで）` : fmtTime(d.last_seen_at)),
    h("td", null, canWrite() ? h("div", { class: "actions" },
      d.platform !== "other" ? h("button", { class: "secondary", onclick: () => enroll(d, out) }, "登録") : null,
      d.paused_until
        ? h("button", { class: "secondary", onclick: () => run(async () => { await api("DELETE", `/v1/devices/${d.id}/pause`); renderOrg(); }, "戻しました") }, "戻す")
        : h("button", { class: "secondary", onclick: () => run(async () => { await api("POST", `/v1/devices/${d.id}/pause`, { minutes: 60 }); renderOrg(); }, "1 時間止めます") }, "今すぐ止める"),
      h("button", { class: "danger", onclick: () => confirm(`${d.name} を消しますか`) && run(async () => { await api("DELETE", `/v1/devices/${d.id}`); renderOrg(); }, "消しました") }, "消す")) : "")));
  const add = canWrite() ? h("form", {
    class: "row card", onsubmit: (ev) => {
      ev.preventDefault();
      const body = formData(ev.target);
      body.org_id = state.org.id;
      run(async () => { await api("POST", "/v1/devices", body); renderOrg(); }, "端末を足しました");
    },
  },
    h("input", { name: "name", placeholder: "端末の名前（例 たろうの iPhone）", required: true }),
    h("select", { name: "platform" }, Object.entries(platforms).map(([v, l]) => h("option", { value: v }, l))),
    h("select", { name: "person_id" }, h("option", { value: "" }, "持ち主なし"), ps.people.map((p) => h("option", { value: p.id }, p.name))),
    h("button", null, "足す")) : null;
  return [h("h2", null, "端末"), add, table(["名前", "種類", "持ち主", "最後の通信", ""], rows), out];
}

async function enroll(d, out) {
  await run(async () => {
    const r = await api("POST", `/v1/devices/${d.id}/enroll`, {});
    const e = r.enrollment || {};
    const items = [h("h3", null, `${d.name} の登録`)];
    if (e.profile_url) items.push(h("p", null, "端末の Safari（Mac はブラウザー）でこの URL を開き、プロファイルを入れます。1 回だけ使えます。"), h("pre", null, e.profile_url));
    else items.push(h("p", null, "端末で次の情報を使って登録します。"), h("pre", null, JSON.stringify(e, null, 2)));
    if (e.expires_at) items.push(h("p", { class: "muted" }, `期限 ${fmtTime(e.expires_at)}`));
    out.replaceChildren(h("div", { class: "card" }, items));
  });
}

// --- 人

async function people() {
  const ps = await api("GET", `/v1/people?org_id=${state.org.id}`);
  const rows = ps.people.map((p) => h("tr", null,
    h("td", null, p.name), h("td", null, p.role === "adult" ? "大人" : "子ども"), h("td", null, p.email || ""),
    h("td", null, canWrite() ? h("button", { class: "danger", onclick: () => confirm(`${p.name} を消しますか`) && run(async () => { await api("DELETE", `/v1/people/${p.id}`); renderOrg(); }, "消しました") }, "消す") : "")));
  const add = canWrite() ? h("form", {
    class: "row card", onsubmit: (ev) => {
      ev.preventDefault();
      const body = formData(ev.target);
      body.org_id = state.org.id;
      run(async () => { await api("POST", "/v1/people", body); renderOrg(); }, "人を足しました");
    },
  },
    h("input", { name: "name", placeholder: "名前", required: true }),
    h("select", { name: "role" }, h("option", { value: "child" }, "子ども"), h("option", { value: "adult" }, "大人")),
    h("input", { name: "email", type: "email", placeholder: "IAM のメールアドレス（任意）" }),
    h("button", null, "足す")) : null;
  return [h("h2", null, "人"), add, table(["名前", "", "メール", ""], rows)];
}

// --- グループ

async function groups() {
  const gs = await api("GET", `/v1/groups?org_id=${state.org.id}`);
  const rows = gs.groups.map((g) => h("tr", null, h("td", null, g.name), h("td", null, g.priority),
    h("td", null, canWrite() ? h("button", { class: "danger", onclick: () => confirm(`${g.name} を消しますか`) && run(async () => { await api("DELETE", `/v1/groups/${g.id}`); renderOrg(); }, "消しました") }, "消す") : "")));
  const add = canWrite() ? h("form", {
    class: "row card", onsubmit: (ev) => {
      ev.preventDefault();
      const body = formData(ev.target);
      body.org_id = state.org.id;
      if (body.priority) body.priority = Number(body.priority);
      run(async () => { await api("POST", "/v1/groups", body); renderOrg(); }, "グループを足しました");
    },
  },
    h("input", { name: "name", placeholder: "グループの名前（例 営業部）", required: true }),
    h("input", { name: "priority", type: "number", placeholder: "優先度（大きいほど勝つ）" }),
    h("button", null, "足す")) : null;
  return [h("h2", null, "グループ"), add, table(["名前", "優先度", ""], rows)];
}

// --- 自動のルール（条件に当たっているあいだ、別のポリシーを使う）

const dayLabels = { sun: "日", mon: "月", tue: "火", wed: "水", thu: "木", fri: "金", sat: "土" };
const reasonLabels = {
  not_encrypted: "暗号化していない", no_screen_lock: "画面ロックが無い", os_outdated: "OS が古い",
  not_reporting: "しばらく報告が無い", policy_not_applied: "ポリシーを受け入れていない", not_managed: "MDM で管理していない",
};

function describeAutomation(a) {
  if (a.trigger === "schedule") {
    return a.windows.map((w) => `${w.days && w.days.length ? w.days.map((d) => dayLabels[d]).join("・") : "毎日"} ${w.start}〜${w.end}`).join("、") + (a.time_zone ? `（${a.time_zone}）` : "（UTC）");
  }
  return "準拠していない：" + a.reasons.map((r) => reasonLabels[r] || r).join("・");
}

async function automations() {
  const [as, ps, gs] = await Promise.all([
    api("GET", `/v1/automations?org_id=${state.org.id}`), api("GET", `/v1/policies?org_id=${state.org.id}`), api("GET", `/v1/groups?org_id=${state.org.id}`)]);
  const policy = Object.fromEntries(ps.policies.map((p) => [p.id, p.name]));
  const group = Object.fromEntries(gs.groups.map((g) => [g.id, g.name]));
  const save = (a, enabled) => {
    const body = { name: a.name, enabled, priority: a.priority, group_ids: a.group_ids, trigger: a.trigger, policy_id: a.policy_id };
    if (a.trigger === "schedule") { body.windows = a.windows; if (a.time_zone) body.time_zone = a.time_zone; } else body.reasons = a.reasons;
    return run(async () => { await api("PUT", `/v1/automations/${a.id}`, body); renderOrg(); }, enabled ? "有効にしました" : "止めました");
  };
  const rows = as.automations.map((a) => h("tr", null,
    h("td", null, a.name, a.enabled ? null : h("div", { class: "muted" }, "止めている")),
    h("td", null, describeAutomation(a)),
    h("td", null, a.group_ids.length ? a.group_ids.map((g) => group[g] || g).join("・") : "すべての端末"),
    h("td", null, policy[a.policy_id] || a.policy_id),
    h("td", null, canWrite() ? h("div", { class: "actions" },
      h("button", { class: "secondary", onclick: () => save(a, !a.enabled) }, a.enabled ? "止める" : "有効にする"),
      h("button", { class: "danger", onclick: () => confirm(`${a.name} を消しますか`) && run(async () => { await api("DELETE", `/v1/automations/${a.id}`); renderOrg(); }, "消しました") }, "消す")) : "")));

  let add = null;
  if (canWrite()) {
    const sched = h("div", { class: "row" },
      Object.entries(dayLabels).map(([v, l]) => h("label", null, h("input", { type: "checkbox", name: "day", value: v }), l)),
      h("input", { name: "start", type: "time", value: "19:00", "aria-label": "始まり" }), "〜",
      h("input", { name: "end", type: "time", value: "21:00", "aria-label": "終わり" }),
      h("input", { name: "time_zone", value: "Asia/Tokyo", "aria-label": "タイムゾーン" }));
    const comp = h("div", { class: "row", hidden: true },
      Object.entries(reasonLabels).map(([v, l]) => h("label", null, h("input", { type: "checkbox", name: "reason", value: v }), l)));
    add = h("form", {
      class: "card", onsubmit: (ev) => {
        ev.preventDefault();
        const f = new FormData(ev.target);
        const body = { org_id: state.org.id, name: f.get("name").trim(), trigger: f.get("trigger"), policy_id: f.get("policy_id"), priority: Number(f.get("priority") || 0) };
        body.group_ids = f.get("group_id") ? [f.get("group_id")] : [];
        if (body.trigger === "schedule") {
          body.windows = [{ days: f.getAll("day"), start: f.get("start"), end: f.get("end") }];
          if (f.get("time_zone").trim()) body.time_zone = f.get("time_zone").trim();
        } else body.reasons = f.getAll("reason");
        run(async () => { await api("POST", "/v1/automations", body); renderOrg(); }, "自動のルールを足しました");
      },
    },
      h("p", { class: "muted" }, "条件に当たっているあいだだけ、端末に別のポリシーを使わせます。外れると元のポリシーに戻ります。曜日を選ばなければ毎日です。"),
      h("div", { class: "row" },
        h("input", { name: "name", placeholder: "名前（例 宿題の時間）", required: true, maxlength: 100 }),
        h("select", { name: "trigger", "aria-label": "条件", onchange: (ev) => { sched.hidden = ev.target.value !== "schedule"; comp.hidden = ev.target.value === "schedule"; } },
          h("option", { value: "schedule" }, "曜日と時間帯"), h("option", { value: "noncompliant" }, "準拠していないとき"))),
      sched, comp,
      h("div", { class: "row" },
        h("select", { name: "group_id", "aria-label": "対象" }, h("option", { value: "" }, "すべての端末"), gs.groups.map((g) => h("option", { value: g.id }, g.name))),
        h("select", { name: "policy_id", "aria-label": "使うポリシー", required: true }, ps.policies.map((p) => h("option", { value: p.id }, p.name))),
        h("input", { name: "priority", type: "number", placeholder: "優先度（大きいほど勝つ）" }),
        h("button", null, "足す")));
  }
  return [h("h2", null, "自動のルール"), add, table(["名前", "条件", "対象", "使うポリシー", ""], rows)];
}

// --- 管理者と招待

const roleNames = { org_admin: "管理者", org_viewer: "見るだけ", server_admin: "サーバー全体の管理者" };

async function admins() {
  if (!canWrite()) return [h("h2", null, "管理者"), h("p", { class: "muted" }, "見るだけの人は管理者の一覧を見られません。")];
  const [as, inv] = await Promise.all([api("GET", "/v1/admins"), api("GET", `/v1/orgs/${state.org.id}/invitations`)]);
  const out = h("div");
  const rows = as.admins.filter((a) => a.org_id === state.org.id).map((a) => h("tr", null,
    h("td", null, a.label || a.subject), h("td", null, roleNames[a.role] || a.role),
    h("td", null, h("button", { class: "danger", onclick: () => confirm("この管理者を外しますか") && run(async () => { await api("DELETE", `/v1/admins/${a.id}`); renderOrg(); }, "外しました") }, "外す"))));
  const invRows = inv.invitations.map((i) => h("tr", null,
    h("td", null, i.label || ""), h("td", null, roleNames[i.role] || i.role), h("td", null, fmtTime(i.expires_at)),
    h("td", null, h("button", { class: "danger", onclick: () => run(async () => { await api("DELETE", `/v1/orgs/${state.org.id}/invitations/${i.id}`); renderOrg(); }, "取り消しました") }, "取り消す"))));
  const form = h("form", {
    class: "row card", onsubmit: (ev) => {
      ev.preventDefault();
      const body = formData(ev.target);
      run(async () => {
        const r = await api("POST", `/v1/orgs/${state.org.id}/invitations`, body);
        out.replaceChildren(h("div", { class: "card" },
          h("h3", null, "招待のコード"),
          h("p", null, "このコードを本人にだけ渡してください。ここでしか表示しません。7 日で切れ、1 回だけ使えます。"),
          h("pre", null, r.code)));
      });
    },
  },
    h("input", { name: "label", placeholder: "誰に送るか（メモ）" }),
    h("select", { name: "role" }, h("option", { value: "org_admin" }, "管理者"), h("option", { value: "org_viewer" }, "見るだけ")),
    h("button", null, "招待のコードを作る"));
  return [h("h2", null, "管理者"), table(["名前", "役割", ""], rows), h("h3", null, "招待"), form, out, table(["メモ", "役割", "期限", ""], invRows)];
}

// --- ルーター

async function routers() {
  let rs;
  try {
    rs = await api("GET", `/v1/orgs/${state.org.id}/radius-clients`);
  } catch (e) {
    if (e.status === 501) return [h("h2", null, "Wi-Fi のルーター"), h("p", { class: "muted" }, "このサーバーでは証明書の Wi-Fi を使っていません。")];
    throw e;
  }
  const out = h("div");
  const rows = rs.radius_clients.map((c) => h("tr", null, h("td", null, c.name),
    h("td", null, c.transport === "radsec" ? "RadSec（証明書）" : h("code", null, c.address)),
    h("td", null, canWrite() ? h("button", { class: "danger", onclick: () => confirm(`${c.name} を消しますか`) && run(async () => { await api("DELETE", `/v1/orgs/${state.org.id}/radius-clients/${c.id}`); renderOrg(); }, "消しました") }, "消す") : "")));
  const address = h("input", { name: "address", placeholder: "ルーターのインターネットのアドレス（例 203.0.113.10）", required: true });
  const transport = h("select", {
    name: "transport", "aria-label": "つなぎ方", onchange: () => {
      const radsec = transport.value === "radsec";
      address.hidden = radsec;
      address.required = !radsec;
    },
  }, h("option", { value: "udp" }, "アドレスと共有の秘密"), h("option", { value: "radsec" }, "RadSec（証明書・TLS）"));
  const add = canWrite() ? h("form", {
    class: "row card", onsubmit: (ev) => {
      ev.preventDefault();
      const body = formData(ev.target);
      if (body.transport === "radsec") delete body.address;
      run(async () => {
        const r = await api("POST", `/v1/orgs/${state.org.id}/radius-clients`, body);
        if (r.transport === "radsec") {
          out.replaceChildren(h("div", { class: "card" },
            h("h3", null, "ルーターに設定する値（RadSec）"),
            h("p", null, "ルーターの RadSec（RADIUS over TLS）の設定に入れます。秘密鍵はここでしか表示しません。"),
            h("pre", null, `RadSec の接続先: ${r.radsec_address}\nサーバー名: ${r.server_name}\n共有の秘密: radsec\n証明書の期限: ${fmtTime(r.not_after)}`),
            h("h3", null, "ルーターの証明書"), h("pre", null, r.client_cert),
            h("h3", null, "ルーターの秘密鍵"), h("pre", null, r.client_key),
            h("h3", null, "サーバーを確かめる認証局"), h("pre", null, r.server_ca)));
          return;
        }
        out.replaceChildren(h("div", { class: "card" },
          h("h3", null, "ルーターに設定する値"),
          h("p", null, "ルーターの WPA2/WPA3 エンタープライズ（RADIUS）の設定に入れます。共有の秘密はここでしか表示しません。"),
          h("pre", null, `RADIUS サーバー名: ${r.server_name}\n共有の秘密: ${r.secret}`)));
      });
    },
  },
    h("input", { name: "name", placeholder: "ルーターの名前（例 本社）", required: true }),
    transport, address,
    h("button", null, "足す")) : null;
  return [h("h2", null, "Wi-Fi のルーター"), add, out, table(["名前", "アドレス", ""], rows)];
}

// --- 操作の記録

async function audit() {
  const a = await api("GET", "/v1/audit");
  const rows = a.events.filter((e) => e.org_id === state.org.id).map((e) => h("tr", null,
    h("td", null, fmtTime(e.at)), h("td", null, e.actor), h("td", null, h("code", null, e.action)), h("td", { class: "muted" }, e.target)));
  return [h("h2", null, "操作の記録"), table(["時刻", "誰が", "何を", "対象"], rows)];
}

// --- 始める

async function boot(selectOrg) {
  try {
    state.me = await api("GET", "/v1/me");
  } catch (e) {
    if (e.status !== 401) say(e.message, "error");
    return;
  }
  document.getElementById("who").replaceChildren(state.me.name, " ",
    h("button", { class: "secondary", onclick: () => run(async () => { await api("POST", "/ui/logout"); renderLogin(); }) }, "ログアウト"));
  if (state.me.roles.length === 0) {
    renderNoRole();
    return;
  }
  const os = await api("GET", "/v1/orgs");
  state.orgs = os.orgs;
  if (state.orgs.length === 0) {
    document.getElementById("app").replaceChildren(h("div", { class: "card" }, h("p", null, isServerAdmin() ? "組織がまだありません。" : "組織が見つかりません。")), signupCard(), acceptCard());
    return;
  }
  state.org = state.orgs.find((o) => o.id === selectOrg) || state.org && state.orgs.find((o) => o.id === state.org.id) || state.orgs[0];
  renderOrg();
}

boot();
