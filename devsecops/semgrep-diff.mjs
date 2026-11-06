// So sánh kết quả Semgrep giữa bản mới (head/) và bản gốc (base/) của cùng các tệp thay đổi.
// Chỉ cảnh báo MỚI (có ở head mà không có ở base) mới làm cổng FAIL: các cảnh báo sẵn có của
// Juice Shop (ứng dụng cố ý chứa lỗ hổng) không chặn mọi thay đổi về sau.
// Dùng: node devsecops/semgrep-diff.mjs <thư mục quét> <semgrep.json>
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const [dir, jsonFile] = process.argv.slice(2)
const report = JSON.parse(readFileSync(jsonFile, 'utf8'))
const lines = new Map()

// Khóa nhận diện cảnh báo: luật + tệp + nội dung dòng code (bỏ khoảng trắng), không dùng số dòng
// để sửa chỗ khác trong tệp không làm cảnh báo cũ thành "mới".
function key (r) {
  const [side, ...rest] = r.path.replace(/^\/scan\//, '').split('/')
  const file = rest.join('/')
  const abs = join(dir, side, file)
  if (!lines.has(abs)) lines.set(abs, existsSync(abs) ? readFileSync(abs, 'utf8').split(/\r?\n/) : [])
  const code = lines.get(abs).slice(r.start.line - 1, r.end.line).join(' ').replace(/\s+/g, ' ').trim()
  return { side, file, k: `${r.check_id}|${file}|${code}` }
}

const count = { base: new Map(), head: new Map() }
const sample = new Map()
for (const r of report.results ?? []) {
  const { side, file, k } = key(r)
  if (!count[side]) continue
  count[side].set(k, (count[side].get(k) ?? 0) + 1)
  if (side === 'head' && !sample.has(k)) sample.set(k, { file, line: r.start.line, rule: r.check_id.split('.').pop(), msg: r.extra?.message ?? '' })
}

let fresh = 0
for (const [k, n] of count.head) {
  const extra = n - (count.base.get(k) ?? 0)
  if (extra <= 0) continue
  fresh += extra
  const s = sample.get(k)
  console.log(`NEW  ${s.file}:${s.line}  [${s.rule}]  ${s.msg.split('\n')[0].slice(0, 140)}`)
}
let resolved = 0
for (const [k, n] of count.base) resolved += Math.max(0, n - (count.head.get(k) ?? 0))
const total = [...count.head.values()].reduce((a, b) => a + b, 0)
console.log(`Semgrep: ${total} cảnh báo trên tệp đã đổi — ${total - fresh} đã có từ bản gốc, ${fresh} MỚI; ${resolved} cảnh báo của bản gốc đã hết sau thay đổi`)
for (const e of report.errors ?? []) if (e.level === 'error') console.log(`ERROR ${e.message ?? e.type}`)
process.exit(fresh > 0 ? 1 : 0)
