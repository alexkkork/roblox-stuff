import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..", "tests", "deobfuscation_corpus", "source");
fs.mkdirSync(root, { recursive: true });

const families = [
  ["arithmetic", (n) => `local a = ${n + 3}\nlocal b = ${n * 2 + 1}\nprint(a * b - math.floor(b / 2))`],
  ["string_transform", (n) => `local value = "sample-${n}"\nprint(string.upper(value):reverse())`],
  ["array_reduce", (n) => `local values = {${n}, ${n + 1}, ${n + 2}, ${n + 3}}\nlocal total = 0\nfor _, value in ipairs(values) do total += value end\nprint(total)`],
  ["dictionary", (n) => `local scores = { alpha = ${n}, beta = ${n + 4} }\nscores.gamma = scores.alpha + scores.beta\nprint(scores.gamma)`],
  ["numeric_loop", (n) => `local result = 1\nfor i = 1, ${(n % 5) + 3} do result *= i end\nprint(result)`],
  ["while_loop", (n) => `local i, total = 0, 0\nwhile i < ${(n % 7) + 4} do i += 1; total += i end\nprint(total)`],
  ["repeat_loop", (n) => `local value = ${n + 9}\nrepeat value -= 3 until value <= 2\nprint(value)`],
  ["closure", (n) => `local function counter(start)\n  local value = start\n  return function(step) value += step; return value end\nend\nlocal nextValue = counter(${n})\nprint(nextValue(2), nextValue(3))`],
  ["recursion", (n) => `local function fib(x)\n  if x < 2 then return x end\n  return fib(x - 1) + fib(x - 2)\nend\nprint(fib(${(n % 5) + 5}))`],
  ["varargs", (n) => `local function sum(...)\n  local total = ${n}\n  for _, value in ipairs({...}) do total += value end\n  return total\nend\nprint(sum(1, 2, 3))`],
  ["multi_return", (n) => `local function values() return ${n}, ${n + 1}, ${n + 2} end\nlocal a, b, c = values()\nprint(c, b, a)`],
  ["table_sort", (n) => `local values = {${n + 7}, ${n}, ${n + 3}, ${n - 1}}\ntable.sort(values)\nprint(table.concat(values, ","))`],
  ["metatable", (n) => `local object = setmetatable({ value = ${n} }, {\n  __index = function(_, key) if key == "double" then return ${n * 2} end end\n})\nprint(object.value, object.double)`],
  ["protected_call", (n) => `local ok, message = pcall(function()\n  if ${n} % 2 == 0 then error("even-${n}") end\n  return "odd-${n}"\nend)\nprint(ok, message)`],
  ["coroutine", (n) => `local thread = coroutine.create(function()\n  coroutine.yield(${n + 1})\n  return ${n + 2}\nend)\nlocal _, first = coroutine.resume(thread)\nlocal _, second = coroutine.resume(thread)\nprint(first, second)`],
  ["iterator", (n) => `local data = { x = ${n}, y = ${n + 1}, z = ${n + 2} }\nlocal total = 0\nfor _, value in pairs(data) do total += value end\nprint(total)`],
  ["if_expression", (n) => `local value = ${n}\nlocal label = if value % 3 == 0 then "three" elseif value % 2 == 0 then "two" else "other"\nprint(label)`],
  ["interpolation", (n) => `local name = "unit"\nlocal count = ${n}\nprint(\`{name}-{count + 1}\`)`],
  ["bit32", (n) => `local encoded = bit32.bxor(${n * 97}, 0x5A5A)\nprint(bit32.band(encoded, 0xFFFF))`],
  ["state_machine", (n) => `local state, steps = "start", 0\nwhile state ~= "done" do\n  steps += 1\n  if state == "start" then state = "work" elseif steps >= ${(n % 4) + 2} then state = "done" end\nend\nprint(state, steps)`],
];

const manifest = [];
for (let index = 1; index <= 100; index += 1) {
  const [family, render] = families[(index - 1) % families.length];
  const variant = Math.floor((index - 1) / families.length) + 1;
  const filename = `${String(index).padStart(3, "0")}_${family}.luau`;
  const source = `-- corpus: ${family}; variant: ${variant}\n${render(index)}\n`;
  fs.writeFileSync(path.join(root, filename), source, "utf8");
  manifest.push({ id: index, family, variant, filename, bytes: Buffer.byteLength(source) });
}

fs.writeFileSync(path.join(root, "manifest.json"), `${JSON.stringify({ version: 1, count: manifest.length, files: manifest }, null, 2)}\n`);
console.log(`Generated ${manifest.length} Luau files in ${root}`);
