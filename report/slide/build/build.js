// Khung dựng slide "phần việc của từng thành viên" — mỗi deck là danh sách slide spec, mỗi spec một kiểu khung.
const path = require("path");
const pptxgen = require("pptxgenjs");
const sharp = require("sharp");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const fa = require("react-icons/fa");
const { applyTheme } = require(path.join(process.env.PPTX_SKILL, "scripts/apply_theme.js"));

const REPO = "E:/banhoaqua/juice-shop";
const SHOT = (f) => `${REPO}/report/screenshots/${f}`;
const NAVY = "14213D", INK = "1B2333", MUTED = "5B6B82", LIGHT = "EEF2F7", CODEBG = "0F1A2E";
const RED = "D9474F", GREEN = "1F8A4C", TEAL = "0E9C8F", AMBER = "C9820F", CODEFG = "F2D16B";

async function icon(Comp, color, size = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color: "#" + color, size }));
  return "image/png;base64," + (await sharp(Buffer.from(svg)).resize(size, size).png().toBuffer()).toString("base64");
}
async function imgSize(file) { const m = await sharp(file).metadata(); return { w: m.width, h: m.height }; }

async function buildDeck(d, outDir) {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE"; // 13.333 x 7.5
  pres.title = `${d.member} — ${d.title}`;
  pres.subject = "SEC4349 · Security as Code cho OWASP Juice Shop — phần việc thành viên";
  const THEME = {
    name: `JuiceShop ${d.mssv}`, headFontFace: "Cambria", bodyFontFace: "Calibri",
    colors: { dk1: INK, lt1: "FFFFFF", dk2: NAVY, lt2: LIGHT, accent1: d.color, accent2: TEAL,
      accent3: RED, accent4: GREEN, accent5: AMBER, accent6: MUTED, hlink: d.color, folHlink: MUTED },
  };
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
  const footer = `OWASP Juice Shop · SEC4349 — ${d.member} · ${d.mssv}`;

  pres.defineSlideMaster({
    title: "DARK", background: { color: NAVY },
    objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.7, y: 2.6, w: 11.9, h: 1.5,
      fontFace: "Cambria", fontSize: 36, bold: true, color: "FFFFFF", valign: "top", align: "left", margin: 0 }, text: "" } }],
    slideNumber: { x: 12.4, y: 7.0, w: 0.6, h: 0.3, fontSize: 10, color: "9FB0C8", align: "right" },
  });
  pres.defineSlideMaster({
    title: "DARKEND", background: { color: NAVY },
    objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.7, y: 0.95, w: 11.9, h: 1.2,
      fontFace: "Cambria", fontSize: 28, bold: true, color: "FFFFFF", valign: "top", align: "left", margin: 0 }, text: "" } }],
    slideNumber: { x: 12.4, y: 7.0, w: 0.6, h: 0.3, fontSize: 10, color: "9FB0C8", align: "right" },
  });
  pres.defineSlideMaster({
    title: "CONTENT", background: { color: "FFFFFF" },
    objects: [
      { placeholder: { options: { name: "kicker", type: "body", x: 0.6, y: 0.3, w: 9.5, h: 0.35,
        fontFace: "Calibri", fontSize: 12, bold: true, color: d.color, charSpacing: 2, margin: 0 }, text: "" } },
      { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.62, w: 12.1, h: 0.75,
        fontFace: "Cambria", fontSize: 28, bold: true, color: NAVY, valign: "top", align: "left", margin: 0 }, text: "" } },
      { text: { text: footer, options: { x: 0.6, y: 7.02, w: 9, h: 0.28, fontSize: 10, color: MUTED, margin: 0 } } },
    ],
    slideNumber: { x: 12.3, y: 7.02, w: 0.6, h: 0.28, fontSize: 10, color: MUTED, align: "right" },
  });

  const I = {};
  for (const [k, comp] of Object.entries(d.icons)) I[k] = await icon(comp, d.color);
  I.check = await icon(fa.FaCheckCircle, GREEN);
  I.cross = await icon(fa.FaTimesCircle, RED);

  pres.addSection({ title: d.mssv });
  const content = (kicker, title) => {
    const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: d.mssv });
    s.addText(kicker.toUpperCase(), { placeholder: "kicker" });
    s.addText(title, { placeholder: "title" });
    return s;
  };
  const pill = (s, text, x, y, w, fill) => s.addText(text, { x, y, w, h: 0.34, fill: { color: fill },
    shape: pres.shapes.ROUNDED_RECTANGLE, rectRadius: 0.08, fontSize: 11, bold: true, color: "FFFFFF",
    align: "center", valign: "middle", margin: 0, isTextBox: true, objectName: "pill" });
  const codeBlock = (s, label, labelColor, code, x, y, w, h, size = 13) => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, fill: { color: CODEBG }, rectRadius: 0.08, objectName: "code-bg" });
    pill(s, label, x + 0.2, y + 0.18, Math.max(2.4, label.length * 0.09 + 0.5), labelColor);
    s.addText(code, { x: x + 0.2, y: y + 0.62, w: w - 0.4, h: h - 0.75, fontFace: "Courier New", fontSize: size,
      color: CODEFG, valign: "top", margin: 0, isTextBox: true, objectName: "code" });
  };
  const card = (s, { x, y, w, h, head, body, ico, fill = LIGHT }) => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, fill: { color: fill }, rectRadius: 0.1, objectName: "card" });
    let tx = x + 0.25;
    if (ico) { s.addImage({ data: ico, x: x + 0.25, y: y + 0.25, w: 0.42, h: 0.42, objectName: "card-icon" }); tx = x + 0.82; }
    s.addText(head, { x: tx, y: y + 0.22, w: x + w - tx - 0.2, h: 0.5, fontSize: 15, bold: true, color: NAVY,
      valign: "middle", margin: 0, isTextBox: true, objectName: "card-head" });
    const paras = (Array.isArray(body) ? body : [body]).map((t, i, a) => ({ text: t, options: { breakLine: i < a.length - 1, paraSpaceAfter: 4 } }));
    s.addText(paras, { x: x + 0.25, y: y + 0.82, w: w - 0.5, h: h - 0.97, fontSize: 14, color: INK, valign: "top",
      margin: 0, isTextBox: true, objectName: "card-body" });
  };
  const picture = async (s, file, x, y, maxW, maxH, name) => {
    const { w, h } = await imgSize(file);
    let pw = maxW, ph = maxW * h / w;
    if (ph > maxH) { ph = maxH; pw = maxH * w / h; }
    s.addImage({ path: file, x: x + (maxW - pw) / 2, y, w: pw, h: ph, altText: name, objectName: name });
    return { w: pw, h: ph };
  };
  const caption = (s, text, x, y, w) => s.addText(text, { x, y, w, h: 0.4, fontSize: 11, italic: true, color: MUTED,
    margin: 0, valign: "top", isTextBox: true, objectName: "caption" });
  const stat = (s, big, label, x, y, w, color) => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h: 1.45, fill: { color: LIGHT }, rectRadius: 0.1, objectName: "stat-bg" });
    s.addText(big, { x: x + 0.25, y: y + 0.12, w: w - 0.5, h: 0.75, fontFace: "Cambria", fontSize: 34, bold: true,
      color: color || NAVY, margin: 0, valign: "middle", isTextBox: true, objectName: "stat-big" });
    s.addText(label, { x: x + 0.25, y: y + 0.85, w: w - 0.5, h: 0.5, fontSize: 12, color: MUTED, margin: 0, valign: "top",
      isTextBox: true, objectName: "stat-label" });
  };
  const head = (labels) => labels.map((t) => ({ text: t, options: { bold: true, color: "FFFFFF", fill: { color: NAVY } } }));
  const stats = (s, list, y, x0 = 0.6, W = 12.1) => {
    const n = list.length, sw = (W - 0.3 * (n - 1)) / n;
    list.forEach((st, i) => stat(s, st[0], st[1], x0 + i * (sw + 0.3), y, sw, st[2]));
  };
  const lines = (t, w, cpi = 10.5) => Math.max(1, Math.ceil(String(t).length / Math.max(1, Math.floor(w * cpi))));
  const textH = (items, w, cpi) => (Array.isArray(items) ? items : [items]).reduce((a, t) => a + lines(t, w, cpi) * 0.24 + 0.1, 0);
  const H = { content, card, codeBlock, picture, caption, stat, stats, pill, head, I, pres };

  const T = {
    cover() {
      const s = pres.addSlide({ masterName: "DARK", sectionTitle: d.mssv });
      s.addText("SEC4349 · DEVOPS VÀ DEVSECOPS · SECURITY AS CODE CHO OWASP JUICE SHOP", { x: 0.7, y: 0.95, w: 11.9, h: 0.4,
        fontSize: 13, bold: true, color: "C9D6EA", charSpacing: 2, margin: 0, isTextBox: true });
      s.addText([{ text: d.member, options: { fontSize: 26, bold: true, color: "FFFFFF" } },
        { text: `   ${d.mssv}`, options: { fontSize: 18, color: "C9D6EA" } }],
        { x: 0.7, y: 1.75, w: 11.9, h: 0.6, margin: 0, valign: "middle", isTextBox: true, objectName: "presenter" });
      s.addText(d.title, { placeholder: "title" });
      s.addText(d.subtitle, { x: 0.7, y: 4.25, w: 11.9, h: 0.5, fontSize: 18, color: "7FD3CB", margin: 0, isTextBox: true });
      let x = 0.7;
      d.pills.forEach((p, i) => { const w = Math.max(2.4, p.length * 0.085 + 0.5); pill(s, p, x, 5.3, w, i === 0 ? d.color : "33415C"); x += w + 0.2; });
    },
    compare(sp) {
      const s = content("So với Juice Shop gốc v20.2.0", sp.title);
      const rows = [head(["Hạng mục", "Juice Shop gốc", "Phần đã làm thêm"]),
        ...sp.rows.map((r) => r.map((t, j) => ({ text: t, options: { bold: j === 0, color: j === 0 ? d.color : j === 1 ? MUTED : INK } })))];
      s.addTable(rows, { x: 0.6, y: 1.6, w: 12.1, colW: [2.5, 3.9, 5.7], fontSize: 14, fontFace: "Calibri",
        border: { type: "solid", pt: 0.75, color: "D5DCE6" }, valign: "middle", margin: [0.08, 0.12, 0.08, 0.12], rowH: sp.rows.length > 5 ? 0.66 : 0.78, objectName: "compare" });
      if (sp.note) s.addText(sp.note, { x: 0.6, y: 6.3, w: 12.1, h: 0.55, fontSize: 14, color: INK, margin: 0, valign: "top", isTextBox: true });
    },
    overview(sp) {
      const s = content("Tổng quan đầu việc", sp.title);
      const cw = (12.1 - 0.3 * 2) / 3, ch = 2.2;
      sp.items.forEach((it, i) => {
        const x = 0.6 + (i % 3) * (cw + 0.3), y = 1.6 + Math.floor(i / 3) * (ch + 0.25);
        s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: cw, h: ch, fill: { color: LIGHT }, rectRadius: 0.1, objectName: "wp-card" });
        s.addText(String(i + 1), { x: x + 0.25, y: y + 0.25, w: 0.48, h: 0.48, shape: pres.shapes.OVAL, fill: { color: d.color },
          fontSize: 16, bold: true, color: "FFFFFF", align: "center", valign: "middle", margin: 0, isTextBox: true, objectName: "wp-num" });
        s.addText(it[0], { x: x + 0.88, y: y + 0.18, w: cw - 1.08, h: 0.62, fontSize: 15, bold: true, color: NAVY, valign: "middle",
          margin: 0, isTextBox: true, objectName: "wp-title" });
        s.addText(it[1], { x: x + 0.25, y: y + 0.92, w: cw - 0.5, h: 0.5, fontFace: "Courier New", fontSize: 11, color: d.color,
          valign: "top", margin: 0, isTextBox: true, objectName: "wp-file" });
        s.addImage({ data: I.check, x: x + 0.25, y: y + 1.55, w: 0.3, h: 0.3, objectName: "wp-check" });
        s.addText(it[2], { x: x + 0.65, y: y + 1.48, w: cw - 0.9, h: 0.85, fontSize: 14, color: INK, valign: "top", margin: 0,
          isTextBox: true, objectName: "wp-result" });
      });
    },
    code2(sp) {
      const s = content(sp.kicker, sp.title);
      codeBlock(s, sp.beforeLabel || "TRƯỚC", sp.beforeColor || RED, sp.before, 0.6, 1.6, 5.9, 3.2);
      codeBlock(s, sp.afterLabel || "SAU KHI SỬA", sp.afterColor || GREEN, sp.after, 6.8, 1.6, 5.9, 3.2);
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.6, y: 5.05, w: 12.1, h: 1.7, fill: { color: "E7F4EC" }, rectRadius: 0.1, objectName: "why-bg" });
      s.addImage({ data: I.check, x: 0.85, y: 5.3, w: 0.42, h: 0.42, objectName: "why-icon" });
      s.addText([{ text: sp.whyHead || "Vì sao hiệu quả", options: { bold: true, color: GREEN, breakLine: true } },
        ...sp.why.map((t, i, a) => ({ text: t, options: { breakLine: i < a.length - 1 } }))],
        { x: 1.45, y: 5.2, w: 11.0, h: 1.45, fontSize: 14, color: INK, valign: "top", margin: 0, paraSpaceAfter: 3, isTextBox: true, objectName: "why" });
    },
    async shotcards(sp) {
      const s = content(sp.kicker, sp.title);
      if (sp.wide) {
        const p = await picture(s, SHOT(sp.shot), 0.6, 1.55, 12.1, sp.maxH || 2.85, sp.shot);
        caption(s, sp.caption, 0.6, 1.55 + p.h + 0.08, 12.1);
        const n = sp.cards.length, cw = (12.1 - 0.3 * (n - 1)) / n, cy = Math.min(4.95, 1.55 + p.h + 0.65);
        const ch = Math.min(6.75 - cy, Math.max(...sp.cards.map((c) => 1.05 + textH(c[1], cw - 0.5))));
        sp.cards.forEach((c, i) => card(s, { x: 0.6 + i * (cw + 0.3), y: cy, w: cw, h: ch, head: c[0], body: c[1], ico: I[c[2]] }));
      } else {
        const p = await picture(s, SHOT(sp.shot), 0.6, 1.6, 7.6, 4.6, sp.shot);
        caption(s, sp.caption, 0.6, 1.6 + p.h + 0.1, 7.6);
        const n = sp.cards.length, ch = Math.min((5.15 - 0.25 * (n - 1)) / n, Math.max(...sp.cards.map((c) => 1.05 + textH(c[1], 3.7))));
        sp.cards.forEach((c, i) => card(s, { x: 8.5, y: 1.6 + i * (ch + 0.25), w: 4.2, h: ch, head: c[0], body: c[1], ico: I[c[2]] }));
      }
    },
    async shotstats(sp) {
      const s = content(sp.kicker, sp.title);
      const p = await picture(s, SHOT(sp.shot), 0.6, 1.55, 12.1, sp.maxH || 3.05, sp.shot);
      s.addText(sp.cmd, { x: 0.6, y: 1.55 + p.h + 0.08, w: 12.1, h: 0.35, fontFace: "Courier New", fontSize: 12, color: MUTED,
        margin: 0, isTextBox: true, objectName: "cmd" });
      stats(s, sp.stats, 5.3);
    },
    gates(sp) {
      const s = content(sp.kicker, sp.title);
      const ph = ["Code", "Build", "Test", "Release", "Deploy", "Operate", "Monitor"], pw = (12.1 - 0.15 * 6) / 7;
      ph.forEach((p, i) => {
        const on = sp.phases.includes(p);
        s.addText(p, { x: 0.6 + i * (pw + 0.15), y: 1.6, w: pw, h: 0.55, shape: pres.shapes.ROUNDED_RECTANGLE, rectRadius: 0.08,
          fill: { color: on ? d.color : LIGHT }, fontSize: 14, bold: on, color: on ? "FFFFFF" : MUTED, align: "center", valign: "middle",
          margin: 0, isTextBox: true, objectName: "phase" });
      });
      const cw = (12.1 - 0.3 * 2) / 3, gh = 1.4 + Math.max(...sp.cols.map((c) => textH(c.body, cw - 0.5)));
      sp.cols.forEach((c, i) => {
        const x = 0.6 + i * (cw + 0.3);
        s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 2.45, w: cw, h: gh, fill: { color: LIGHT }, rectRadius: 0.1, objectName: "gate-card" });
        s.addText(c.when, { x: x + 0.25, y: 2.6, w: cw - 0.5, h: 0.45, fontFace: "Courier New", fontSize: 15, bold: true, color: NAVY,
          margin: 0, valign: "middle", isTextBox: true, objectName: "gate-when" });
        s.addImage({ data: c.blocked ? I.cross : I.check, x: x + 0.25, y: 3.15, w: 0.36, h: 0.36, objectName: "gate-icon" });
        s.addText(c.result, { x: x + 0.72, y: 3.1, w: cw - 0.95, h: 0.46, fontSize: 15, bold: true, color: c.blocked ? RED : GREEN,
          margin: 0, valign: "middle", isTextBox: true, objectName: "gate-result" });
        s.addText(c.body, { x: x + 0.25, y: 3.7, w: cw - 0.5, h: gh - 1.35, fontSize: 14, color: INK, margin: 0, valign: "top",
          isTextBox: true, objectName: "gate-body" });
      });
      s.addText(sp.note, { x: 0.6, y: 2.45 + gh + 0.3, w: 12.1, h: 0.9, fontSize: 15, color: INK, margin: 0, valign: "top", isTextBox: true, objectName: "note" });
    },
    files(sp) {
      const s = content("Tệp đã thêm / sửa", sp.title);
      const rows = [head(["Việc", "Tệp"]), ...sp.rows.map((r) => [{ text: r[0], options: { color: INK } },
        { text: r[1], options: { color: d.color, fontFace: "Courier New", fontSize: 11 } }])];
      s.addTable(rows, { x: 0.6, y: 1.6, w: 8.4, colW: [4.55, 3.85], fontSize: 13, fontFace: "Calibri",
        border: { type: "solid", pt: 0.75, color: "D5DCE6" }, valign: "middle", margin: [0.05, 0.1, 0.05, 0.1], rowH: 0.48, objectName: "files" });
      const th = 0.85 + 0.85 * sp.tools.length;
      s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 9.2, y: 1.6, w: 3.5, h: th, fill: { color: CODEBG }, rectRadius: 0.1, objectName: "tools-bg" });
      s.addText("CÔNG CỤ · PHA", { x: 9.45, y: 1.78, w: 3.0, h: 0.35, fontSize: 12, bold: true, color: "7FD3CB", charSpacing: 2, margin: 0, isTextBox: true });
      s.addText(sp.tools.flatMap((t, i, a) => [
        { text: t[0], options: { fontFace: "Courier New", fontSize: 14, bold: true, color: CODEFG, breakLine: true } },
        { text: t[1], options: { fontSize: 13, color: "C9D6EA", breakLine: i < a.length - 1, paraSpaceAfter: 10 } },
      ]), { x: 9.45, y: 2.25, w: 3.05, h: th - 0.8, margin: 0, valign: "top", isTextBox: true, objectName: "tools" });
    },
    end(sp) {
      const s = pres.addSlide({ masterName: "DARKEND", sectionTitle: d.mssv });
      s.addText("KẾT LUẬN", { x: 0.7, y: 0.55, w: 6, h: 0.4, fontSize: 13, bold: true, color: "7FD3CB", charSpacing: 2, margin: 0, isTextBox: true });
      s.addText(sp.headline, { placeholder: "title" });
      const cols = [["ĐÃ LÀM ĐƯỢC", sp.done, "7FD3CB"], ["GIỚI HẠN", sp.limits, "F2B8BC"], ["HƯỚNG MỞ RỘNG", sp.next, CODEFG]];
      const cw = (11.9 - 0.3 * 2) / 3, eh = 0.95 + Math.max(...cols.map((c) => textH(c[1], cw - 0.75)));
      cols.forEach(([h, items, col], i) => {
        const x = 0.7 + i * (cw + 0.3);
        s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 2.45, w: cw, h: eh, fill: { color: "1E2E52" }, rectRadius: 0.1, objectName: "end-card" });
        s.addText(h, { x: x + 0.25, y: 2.62, w: cw - 0.5, h: 0.4, fontSize: 13, bold: true, color: col, charSpacing: 1, margin: 0, isTextBox: true });
        s.addText(items.map((t, j, a) => ({ text: t, options: { bullet: { indent: 16 }, breakLine: j < a.length - 1, paraSpaceAfter: 8 } })),
          { x: x + 0.25, y: 3.1, w: cw - 0.5, h: eh - 0.75, fontSize: 14, color: "E6ECF5", margin: 0, valign: "top", isTextBox: true, objectName: "end-list" });
      });
    },
  };

  for (const sp of d.slides) {
    if (sp.type === "custom") await sp.fn(H, d);
    else await T[sp.type](sp);
  }
  const file = path.join(outDir, d.file);
  await pres.writeFile({ fileName: file });
  await applyTheme(file, THEME);
  return file;
}

module.exports = { buildDeck, fa, SHOT, NAVY, INK, MUTED, LIGHT, CODEBG, RED, GREEN, TEAL, AMBER, CODEFG };
