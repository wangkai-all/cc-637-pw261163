/* Merkle snapshot diff tool — vanilla JS SPA */
"use strict";

const $ = (sel) => document.querySelector(sel);
const api = async (path, opts = {}) => {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(data.error || "request failed"),
    { status: res.status, data });
  return data;
};
const esc = (s) => String(s).replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const shortHash = (h) => h ? h.slice(0, 16) + "…" : "–";
const fmt = (v) => v === null ? "<span class='warn'>NULL</span>"
  : v === "" ? "<span class='warn'>空字符串</span>" : esc(JSON.stringify(v));

// ---------- tabs ----------
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $("#tab-" + btn.dataset.tab).classList.add("active");
    if (["diff", "check", "sync"].includes(btn.dataset.tab)) refreshSnapshots();
  });
});

// ---------- build ----------
let pickedFile = null;
$("#build-file").addEventListener("change", (e) => {
  pickedFile = e.target.files[0] || null;
  $("#build-file-label").textContent = pickedFile ? pickedFile.name : "选择数据文件…";
});

const toBase64 = (buf) => new Promise((resolve, reject) => {
  const blob = new Blob([buf]);
  const reader = new FileReader();
  reader.onload = () => resolve(reader.result.split(",")[1]);
  reader.onerror = reject;
  reader.readAsDataURL(blob);
});

$("#btn-build").addEventListener("click", async () => {
  const out = $("#build-output");
  out.textContent = "构建中…";
  try {
    if (!pickedFile) throw new Error("请先选择数据文件");
    const name = $("#build-name").value.trim();
    if (!name) throw new Error("请填写快照名称");
    const typesRaw = $("#build-types").value.trim();
    const body = {
      name,
      format: $("#build-format").value,
      content: await toBase64(await pickedFile.arrayBuffer()),
      key_fields: $("#build-keys").value.trim()
        ? $("#build-keys").value.split(",").map((s) => s.trim()).filter(Boolean)
        : null,
      types: typesRaw ? JSON.parse(typesRaw) : null,
    };
    const fail = $("#build-fail-after").value.trim();
    if (fail) body.fail_after_nodes = Number(fail);
    try {
      const manifest = await api("/api/build", {
        method: "POST", body: JSON.stringify(body) });
      out.textContent = "构建完成\n" + JSON.stringify(manifest, null, 2);
    } catch (err) {
      if (err.status === 202 && err.data && err.data.interrupted) {
        out.textContent = "已模拟中断（根节点尚未发布）：\n"
          + JSON.stringify(err.data, null, 2)
          + "\n\n点击「从中断点继续」即可从 journal 已核对节点续建。";
      } else throw err;
    }
    await refreshSnapshots();
  } catch (err) {
    out.textContent = "失败：" + err.message
      + (err.data && err.data.duplicates
        ? "\n重复主键：" + JSON.stringify(err.data.duplicates, null, 2) : "");
  }
});

$("#btn-resume").addEventListener("click", async () => {
  const out = $("#build-output");
  try {
    const name = $("#build-name").value.trim();
    if (!name) throw new Error("请填写要续建的快照名称");
    const manifest = await api("/api/resume", {
      method: "POST", body: JSON.stringify({ name }) });
    out.textContent = "续建完成，新根已发布\n" + JSON.stringify(manifest, null, 2);
    await refreshSnapshots();
  } catch (err) {
    out.textContent = "续建失败：" + err.message;
  }
});

$("#btn-demo").addEventListener("click", async () => {
  const out = $("#build-output");
  out.textContent = "正在生成示例快照 v1 / v2…";
  try {
    const [mod] = await Promise.all([import("/demo-data.js")]);
    const types = mod.SCHEMA_TYPES;
    for (const [name, rows] of [["demo-v1", mod.BASE_ROWS],
                                ["demo-v2", mod.TARGET_ROWS]]) {
      const body = { name, format: "json",
        content: btoa(unescape(encodeURIComponent(JSON.stringify(rows)))),
        key_fields: mod.KEY_FIELDS, types };
      try {
        await api("/api/build", { method: "POST", body: JSON.stringify(body) });
      } catch (err) {
        if (err.status !== 400 || !/already exists/.test(err.message)) throw err;
      }
    }
    out.textContent = "示例已就绪：demo-v1 与 demo-v2\n"
      + "包含场景：桶边界插入准备、null/空串更正、小数等价表示、删除最后一行。\n"
      + "请到「版本对比」选择两版。";
    await refreshSnapshots();
  } catch (err) {
    out.textContent = "示例生成失败：" + err.message;
  }
});

// ---------- snapshot list ----------
async function refreshSnapshots() {
  const snaps = await api("/api/snapshots");
  const tbody = $("#snapshot-table tbody");
  tbody.innerHTML = snaps.map((s) => `
    <tr><td>${esc(s.name)}</td>
    <td>${s.complete ? "<span class='ok'>完整</span>"
                      : "<span class='warn'>未完成（可续建）</span>"}</td>
    <td>${s.manifest ? s.manifest.record_count : "–"}</td>
    <td><code>${s.manifest ? shortHash(s.manifest.root_hash) : "–"}</code></td>
    </tr>`).join("");
  const opts = snaps.filter((s) => s.complete)
    .map((s) => `<option value="${esc(s.name)}">${esc(s.name)}</option>`).join("");
  for (const id of ["diff-base", "diff-target", "check-name", "corrupt-name",
                    "sync-base", "sync-target", "sync-receiver"]) {
    const sel = $("#" + id);
    const prev = sel.value;
    sel.innerHTML = opts;
    if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
  }
  if ($("#diff-target").options[1]) $("#diff-target").selectedIndex = 1;
  if ($("#sync-target").options[1]) $("#sync-target").selectedIndex = 1;
}
$("#btn-refresh").addEventListener("click", refreshSnapshots);

// ---------- diff ----------
let lastDiff = null;
$("#btn-diff").addEventListener("click", async () => {
  const out = $("#diff-output");
  out.textContent = "比较中…";
  try {
    const base = $("#diff-base").value, target = $("#diff-target").value;
    if (!base || !target) throw new Error("请选择两个快照");
    lastDiff = await api(`/api/diff?base=${encodeURIComponent(base)}`
      + `&target=${encodeURIComponent(target)}`);
    renderDiff(lastDiff);
    out.textContent = (lastDiff.complete ? "" : "⚠ 存在损坏，结果不完整\n")
      + JSON.stringify({
        root_equal: lastDiff.root_equal,
        schema_changed: lastDiff.schema_changed,
        counts: lastDiff.counts,
        tree_walk: lastDiff.tree_walk,
        full_scan: lastDiff.full_scan,
        corruptions: lastDiff.corruptions,
      }, null, 2);
  } catch (err) {
    out.textContent = "差异失败：" + err.message;
  }
});

function renderDiff(d) {
  const w = d.tree_walk, fs = d.full_scan || {};
  $("#st-nodes").textContent = w.nodes_loaded;
  $("#st-rows").textContent = w.rows_loaded;
  $("#st-skip").textContent = w.subtrees_skipped_equal;
  $("#st-desc").textContent = w.subtrees_descended;
  $("#st-scan-b").textContent = fs.base_rows_read ?? "–";
  $("#st-scan-t").textContent = fs.target_rows_read ?? "–";
  $("#st-verdict").innerHTML = d.verified
    ? `<span class="ok">✓ 逐行全量校验通过：Merkle 剪枝结果与全表逐行比较完全一致</span>`
    : `<span class="bad">✗ 校验未通过${fs.errors && fs.errors.length
        ? "：" + esc(fs.errors.join("; ")) : "（存在损坏节点）"}</span>`;
  $("#c-ins").textContent = d.counts.inserted;
  $("#c-del").textContent = d.counts.deleted;
  $("#c-mod").textContent = d.counts.modified;
  renderTree(d.tree);
  renderChanges(d.changes);
}

function renderTree(node) {
  const root = $("#tree-view");
  if (!node) { root.innerHTML = "<p class='hint'>根节点损坏，无法生成树视图</p>"; return; }
  root.innerHTML = "";
  root.appendChild(treeNode(node, 0));
}

function treeNode(node, depth) {
  const wrap = document.createElement("div");
  wrap.className = "tnode";
  const row = document.createElement("div");
  row.className = "trow";
  const hasChildren = node.children && node.children.length;
  const label = node.kind === "leaf"
    ? `${node.id}（桶，${node.status === "same" ? "" :
        (node.inserted || 0) + "增 " + (node.deleted || 0) + "删 "
        + (node.modified || 0) + "改"}）`
    : node.id + (node.kind === "root" ? "（根）" : "（一级节点）");
  const badges = [];
  if (node.status === "same") badges.push("<span class='badge same'>相同</span>");
  if (node.status === "changed") badges.push("<span class='badge changed'>变动</span>");
  if (node.status === "corrupt") badges.push("<span class='badge corrupt'>损坏</span>");
  badges.push(node.loaded
    ? "<span class='badge loaded'>已读取节点</span>"
    : "<span class='badge skipped'>未读取·剪枝</span>");
  row.innerHTML = `<span class="tid">${esc(label)}</span>${badges.join("")}
    <span class="hash">${esc(shortHash(node.base_hash))}</span>
    ${node.base_hash === node.target_hash ? "" :
      `<span>→</span><span class="hash">${esc(shortHash(node.target_hash))}</span>`}`;
  if (hasChildren) {
    row.classList.add("clickable");
    const childBox = document.createElement("div");
    childBox.className = "children" + (depth < 1 ? " open" : "");
    node.children.forEach((c) => childBox.appendChild(treeNode(c, depth + 1)));
    row.addEventListener("click", () => childBox.classList.toggle("open"));
    wrap.append(row, childBox);
  } else {
    wrap.appendChild(row);
  }
  return wrap;
}

function renderChanges(changes) {
  const box = $("#change-list");
  if (!changes.length) { box.innerHTML = "<p class='hint'>无行级差异</p>"; return; }
  box.innerHTML = changes.map((c) => {
    const cls = c.type;
    const title = { inserted: "新增", deleted: "删除", modified: "修改" }[c.type];
    let body = "";
    if (c.type === "inserted") body = rowTable(c.target);
    if (c.type === "deleted") body = rowTable(c.base);
    if (c.type === "modified") body = compareTable(c.base, c.target);
    return `<div class="change"><div class="head">
      <span class="pill ${cls}">${title}</span>
      <code>桶 ${c.bucket} · 主键 ${esc(JSON.stringify(c.pk))}</code></div>${body}</div>`;
  }).join("");
}
function rowTable(row) {
  return "<table>" + Object.entries(row)
    .map(([k, v]) => `<tr><td>${esc(k)}</td><td>${fmt(v)}</td></tr>`).join("")
    + "</table>";
}
function compareTable(base, target) {
  const keys = [...new Set([...Object.keys(base), ...Object.keys(target)])];
  return "<table>" + keys.map((k) => {
    const same = JSON.stringify(base[k]) === JSON.stringify(target[k]);
    return `<tr><td>${esc(k)}</td>
      <td class="${same ? "" : "diff-old"}">${fmt(base[k])}</td>
      <td class="${same ? "" : "diff-new"}">${fmt(target[k])}</td></tr>`;
  }).join("") + "</table>";
}

$("#btn-download").addEventListener("click", () => {
  if (!lastDiff) return alert("请先执行一次差异比较");
  const d = lastDiff;
  location.href = `/api/diff/download?base=${encodeURIComponent(d.base)}`
    + `&target=${encodeURIComponent(d.target)}`;
});

// ---------- check / corruption ----------
$("#btn-check").addEventListener("click", async () => {
  const out = $("#check-output");
  try {
    const name = $("#check-name").value;
    const report = await api(`/api/check?name=${encodeURIComponent(name)}`);
    out.textContent = (report.ok ? "✓ 校验通过\n" : "✗ 发现损坏\n")
      + JSON.stringify(report, null, 2);
  } catch (err) { out.textContent = "校验失败：" + err.message; }
});

$("#btn-corrupt").addEventListener("click", async () => {
  const out = $("#corrupt-output");
  try {
    const body = {
      name: $("#corrupt-name").value,
      kind: $("#corrupt-kind").value,
      target: $("#corrupt-target").value.trim() || null,
    };
    const res = await api("/api/corrupt", {
      method: "POST", body: JSON.stringify(body) });
    out.textContent = "已注入破坏：\n" + JSON.stringify(res, null, 2)
      + "\n\n现在执行「逐节点校验」或回到版本对比，观察受影响范围被定位到具体桶。";
  } catch (err) { out.textContent = "注入失败：" + err.message; }
});

// ---------- sync ----------
let pickedPkg = null;
$("#sync-file").addEventListener("change", (e) => {
  pickedPkg = e.target.files[0] || null;
  $("#sync-file-label").textContent = pickedPkg ? pickedPkg.name : "选择同步包 JSON…";
});
$("#btn-sync-pkg").addEventListener("click", () => {
  const base = $("#sync-base").value, target = $("#sync-target").value;
  if (!base || !target) return alert("请选择基线与目标快照");
  location.href = `/api/sync/package?base=${encodeURIComponent(base)}`
    + `&target=${encodeURIComponent(target)}`;
});
$("#btn-sync-apply").addEventListener("click", async () => {
  const out = $("#sync-output");
  try {
    if (!pickedPkg) throw new Error("请先选择同步包文件");
    const pkg = JSON.parse(await pickedPkg.text());
    const newName = $("#sync-new").value.trim();
    if (!newName) throw new Error("请填写应用后的新快照名称");
    const res = await api("/api/sync/apply", {
      method: "POST",
      body: JSON.stringify({
        receiver: $("#sync-receiver").value,
        new_snapshot: newName, package: pkg,
      }),
    });
    out.textContent = "应用成功并已核对目标根：\n" + JSON.stringify(res, null, 2);
    await refreshSnapshots();
  } catch (err) {
    out.textContent = "同步被拒绝/失败（接收端数据未被修改）：\n" + err.message;
  }
});

refreshSnapshots();
