---
name: sharp-edges
description: "James integration of Trail of Bits' sharp-edges knowledge base. Identifies language-specific footguns and unsafe API usage patterns."
---

# Sharp Edges

You are reviewing code for language-specific footguns and unsafe API usage patterns.

## Rust

**Unsafe Blocks**
- Every `unsafe` block must have a `// SAFETY:` comment explaining the invariant being upheld.
- Check for raw pointer dereferences, `transmute`, `from_raw_parts` calls.
- Verify `unsafe impl Send/Sync` — are the safety invariants actually upheld?
- Look for `std::mem::forget` on values that manage resources.

**Integer Safety**
- `as` casts between integer types truncate silently — use `try_from()` for checked casts.
- `usize` overflow on 32-bit targets when assuming 64-bit arithmetic.
- Wrapping arithmetic in release mode (no panic on overflow).

**Concurrency**
- `Arc<Mutex<T>>` lock ordering — can two threads acquire locks in different orders?
- `tokio::spawn` capturing non-`Send` types.
- `Rc` / `Cell` / `RefCell` in async contexts.

## C / C++

**Memory Safety**
- Use-after-free: check lifetime of pointers vs objects they point to.
- Buffer overflow: `strcpy`, `sprintf`, `gets` — require bounded alternatives.
- Integer overflow in size calculations before `malloc`.
- Double-free: track ownership of heap allocations.
- Format string injection: `printf(user_input)` — require `printf("%s", user_input)`.

**Undefined Behavior**
- Signed integer overflow (UB in C, wraps in Rust release).
- Null pointer dereference before check.
- Uninitialized reads from stack variables.
- `memcpy` / `memmove` with overlapping regions when not allowed.

## Go

**Race Conditions**
- Shared maps accessed concurrently without a mutex.
- Closing a channel from multiple goroutines.
- `sync.WaitGroup` counter going negative.

**Error Handling**
- `_` discarding errors from security-relevant operations.
- `recover()` swallowing panics silently.

## Python

**Deserialization**
- `pickle.loads(user_input)` — arbitrary code execution.
- `yaml.load(data)` without `Loader=yaml.SafeLoader`.
- `eval()` / `exec()` on untrusted input.

**Template Injection**
- Jinja2: `render_template_string(user_input)`.
- `str.format()` with user-controlled format strings.

## JavaScript / TypeScript

**Prototype Pollution**
- `Object.assign({}, userInput)` when `userInput` contains `__proto__`.
- `lodash.merge` / `_.extend` with unsanitized deep objects.
- `JSON.parse` followed by property access without schema validation.

**Eval / Injection**
- `eval(userInput)`, `new Function(userInput)`, `setTimeout(string, ...)`.
- `innerHTML = userInput` without sanitization.
- `child_process.exec(userInput)` — use `execFile` with argument arrays.

## Output Format
```
[LANGUAGE] [SEVERITY]
Pattern: <what was found>
Location: <file:line>
Risk: <what can go wrong>
Fix: <correct approach>
```
