# 重复计数驱动的资源耗尽分析（construct 库）

分析对象：本仓库 `construct/core.py`（commit 28c6e57）。
威胁模型：解析器接收不可信二进制输入，其中的计数字段（length/count prefix）完全由攻击者控制。

## 1. 受影响的三类重复结构及其实际资源边界

### 1.1 定长数组 `Array`（core.py:2493）

解释执行（`_parse`，core.py:2525）：

```python
count = evaluate(self.count, context)
if not 0 <= count:
    raise RangeError(...)
obj = ListContainer()
for i in range(count):
    e = self.subcon._parsereport(stream, context, path)
    obj.append(e)
```

- 唯一的校验是 `count >= 0`。**没有任何"剩余字节是否够 count 个元素"的前置检查**。
- 若子构造消耗字节（如 `Int32ul`）：迭代到流耗尽时 `stream_read` 抛 `StreamError`，快速失败。内存上界 ≈ `剩余字节数 / 元素大小`，是有界的。
- 若子构造不消耗字节（`Pass`、`Computed(...)`、`Terminated`、纯 `Check` 等 sizeof 为 0 的构造）：循环次数完全由攻击者的计数字段决定，每次迭代向 `ListContainer` 追加一个元素，**内存和 CPU 均无界**。`count` 取自 `Int32ub` 时上限约 42.9 亿次迭代。
- `discard=True` 只是不 append，**循环照样执行 count 次**，是纯 CPU 空转，不能作为缓解手段。

编译执行（`_emitparse`，core.py:2560）：

```python
ListContainer((subcon) for i in range(count))
```

- 语义同样是"先信计数、再逐个解析"，没有剩余量检查，零消耗元素下同样无界，且实测比解释执行**更耗内存**（生成器一次性物化，见 §3 数据）。
- 编译版**完全忽略 `discard` 参数**：`discard=True` 时仍然物化整个 `ListContainer`，比解释执行更差。

### 1.2 前缀计数数组 `PrefixedArray`（core.py:4934）

`PrefixedArray(countfield, subcon)` 是 `FocusedSeq("count"/Rebuild(countfield,...), "items"/subcon[this.count])` 的宏，计数直接来自输入流，是本次风险最集中的入口。

- 解释执行：等价于 `Array(this.count, subcon)`，行为同上。
- 编译执行（`_emitparse`，core.py:4963）：`ListContainer((subcon) for i in range(countfield_parse))`，计数在运行时从流中读出后直接进 `range()`，同样无校验。
- 对比 `Prefixed`（按字节数前缀，core.py:4862）：它先 `stream_read(stream, length)` 把 `length` 字节整体读出来，长度超过剩余量时**一次性快速失败**，且子解析被限制在子流内。`PrefixedArray` 没有这个保护，这是两者安全性的本质差别。

### 1.3 条件重复 `RepeatUntil`（core.py:2637）

解释执行（`_parse`，core.py:2670）是 `for i in itertools.count()` 的无限循环，唯一的退出条件是谓词为真：

- 子构造消耗字节时：谓词永不满足的情况下，迭代到 EOF 抛 `StreamError`，有界。
- 子构造零消耗（如 `Pass`）且谓词永不满足（`lambda *_: False`，或谓词依赖的值永远算不出来）：**真正的无限循环**，每轮 append 一次，内存单调增长直到 OOM，无任何错误路径可达。
- 编译执行（`_emitparse`，core.py:2706）生成 `while True` 循环，同样无界；且谓词 lambda 会被 f-string 直接内联进生成代码，`RepeatUntil(lambda ...).compile()` 实测抛 `SyntaxError`（lambda 的 repr 不是合法表达式），即编译路径对常见用法本身就是坏的。

### 1.4 对照：`GreedyRange`

`GreedyRange` 没有 `_emitparse`，编译时回退到 `linkedparsers`（即解释执行）。它在子构造抛异常时回 seek 并正常返回，EOF 是其固有终止条件，因此消耗型元素下有界；但零消耗元素（如 `GreedyRange(Pass)`）同样无限循环——不过它不以前缀计数为驱动，不属于本次"计数字段"威胁的主路径。

## 2. 解释执行 vs 编译执行：计数处理与错误传播对比

| 维度 | 解释执行 | 编译执行 |
|---|---|---|
| 计数上限校验 | 仅 `count >= 0`，无剩余量检查 | 无任何检查，`count` 直接进 `range()` |
| 负数计数 | `RangeError("invalid count")`（Array._parse） | **静默返回空列表**（`range(-1)` 为空），错误被吞掉 |
| 元素零消耗 + 大计数 | 无界迭代 + 无界内存 | 同样无界，且内存更差（生成器物化） |
| `discard=True` | 不 append，但仍空转 count 次 | **被忽略**，仍物化整个列表 |
| 元素读不足（如 `Bytes(8)` 只剩 2 字节） | `stream_read` 抛 `StreamError` | 编译码是 `io.read(n)`，**静默返回短读数据**，不产生错误 |
| `RepeatUntil` 谓词 | 正常运行 | lambda 谓词导致 `SyntaxError`，编译直接失败 |
| 消耗型元素 + 超大计数 | 迭代至 EOF 抛 `StreamError`，快速失败 | 同左（但短读不报错，见上行） |

**在剩余字节不足时仍持续分配/迭代的输入**，共同特征是"每轮迭代不消耗（或消耗极少）输入"：

1. `Array`/`PrefixedArray` 的子构造 sizeof 为 0（`Pass`、`Computed`、`Terminated` 等）：计数多大就迭代多大，与剩余字节完全脱钩。
2. `RepeatUntil` 谓词永不满足且子构造零消耗：无限循环。
3. 编译执行下连"消耗型元素"的兜底都削弱了：`io.read(n)` 短读不抛错，元素在 EOF 后仍可能"解析成功"（返回短字节串），使 `Array`/`RepeatUntil` 在流耗尽后继续迭代。

## 3. 可复现的畸形样本与实测影响

以下样本均在本仓库代码上实测（Python 3，直接 `parse()`）：

**样本 A：零消耗元素 + 大计数前缀（内存耗尽）**

```python
d = PrefixedArray(Int32ub, Pass)
d.parse((30_000_000).to_bytes(4, "big"))   # 仅 4 字节输入
```

- 解释执行：3.16 s，峰值 RSS **255 MB**，返回 3000 万个 `None`。
- 编译执行：0.74 s，峰值 RSS **484 MB**。
- 计数取 `0xFFFFFFFF`（4 字节输入即可构造）时迭代约 42.9 亿次，内存需求数十 GB，实际即 OOM/长时间 DoS。

**样本 B：`discard=True` 不能缓解（CPU 耗尽）**

```python
Array(30_000_000, Pass, discard=True).parse(b"")   # 2.63 s 纯 CPU 空转
Array(20_000_000, Pass, discard=True).compile().parse(b"")  # 编译版忽略 discard，另分配 209 MB
```

**样本 C：永不终止的条件重复（无限循环）**

```python
RepeatUntil(lambda x, lst, ctx: False, Pass).parse(b"")   # 空输入，永不返回
```

实测 3 秒闹钟超时仍在循环，list 持续增长。等价地，`RepeatUntil` 谓词若引用攻击者可控但永不出现的值（如 `lst[-2:] == [0,0]` 而元素恒非 0）且元素零消耗，效果相同。

**样本 D：负数计数的错误传播分歧**

```python
Struct("n" / Int8sb, "items" / Byte[this.n]).parse(b"\xff")
# 解释执行: RangeError("invalid count -1")
# 编译执行: 静默返回 items=[]，畸形输入被当作合法
```

**样本 E：编译执行吞掉短读**

```python
Bytes(8).compile().parse(b"ab")   # 返回 b'ab'，不抛 StreamError
```

影响范围：任何用本库解析不可信输入、且 schema 中含 `Array(动态计数, 零尺寸子构造)`、`PrefixedArray(..., 零尺寸子构造)`、`RepeatUntil(不可证终止谓词, 零尺寸子构造)` 的应用。协议中常见的 `Computed`、`Check`、`Pass` 与数组组合（例如"重复 N 次校验/填充"）都会命中。即使子构造消耗字节，编译路径的短读静默（样本 E）也会让 EOF 兜底失效。

## 4. 基于输入剩余量的拒绝方案

核心原则：**在相信计数字段之前，先证明剩余输入足够**。建议按层次实施：

### 4.1 Array/PrefixedArray：解析前做剩余量预检（主要修复）

在 `Array._parse`（core.py:2525）取得 `count` 后、进入循环前：

```python
count = evaluate(self.count, context)
if not 0 <= count:
    raise RangeError("invalid count %s" % (count,), path=path)
try:
    elemsize = self.subcon._sizeof(context, path)
except SizeofError:
    elemsize = None
if elemsize is not None:
    if elemsize == 0 and count > 0:
        # 零尺寸元素的重复是 schema 缺陷或畸形输入, 直接拒绝
        raise RangeError("count %d with zero-size subcon would loop without consuming input" % count, path=path)
    # 可 seek 的流: 用剩余字节数做上界拒绝
    try:
        remaining = stream_remaining(stream)  # seek(0,2) 取总长减 tell(), 再 seek 回去
    except Exception:
        remaining = None
    if remaining is not None and count * elemsize > remaining:
        raise StreamError("count %d needs %d bytes, only %d remain" % (count, count*elemsize, remaining), path=path)
```

要点：

- `sizeof` 可静态求得时（定长元素），用 `count * elemsize > remaining` 在 **O(1)** 时间内拒绝，畸形计数（如 4 字节输入声称 40 亿元素）在第一次循环前就被打掉。
- `sizeof == 0` 的元素重复本身没有合法解析语义（结果只依赖 count 不依赖输入），应直接拒绝；这同时封死样本 A/B。
- `sizeof` 不可静态求得（变长元素）时退化为运行时兜底：每轮迭代记录 `stream_tell`，若连续迭代位置不前进（zero-progress），立即抛 `RepeatError`/`StreamError`。这是 `PrefixedArray` 在 `VarInt` 计数 + 变长元素下的必要补充。
- `PrefixedArray` 无需单独改：它复用 `Array` 的 `_parse`；其编译版 `_emitparse`（core.py:4963）应同样生成预检代码，或保守起见让计数来自流时回退到解释路径。

### 4.2 RepeatUntil：零进度检测 + 迭代上限

在 `_parse` 循环中记录上一轮 `stream_tell(stream)`，若本轮解析后位置未变且谓词未满足，抛 `RepeatError("subcon consumed no input and predicate not met, aborting")`。对不可 seek 流，至少提供一个可选的 `maxcount` 上限（默认如 `2**31`）作为最后防线。这封死样本 C。

### 4.3 编译路径对齐错误语义

- 编译版 `Array`/`PrefixedArray` 生成与解释版一致的 `count >= 0` 检查（修复样本 D 的静默空列表）。
- 编译版 `Bytes`/`FormatField` 的 `io.read(n)` 应包装为"读不足即抛 `StreamError`"（修复样本 E），否则 EOF 兜底在编译路径整体失效。
- 编译版 `Array` 应尊重 `discard`（生成不物化的循环），与解释版对齐。

### 4.4 应用层立即可用的缓解（不改库）

在库修复前，使用方可自行约束：

- 优先用 `Prefixed`（字节数前缀）替代 `PrefixedArray`：`Prefixed(lenfield, GreedyRange(subcon))` 的长度先整体读入并快速失败，天然有界。
- 给计数加上界：`"count" / Rebuild(Check(lambda n: n <= MAX_REASONABLE), Int32ub)` 或 `ExprValidator`，把上限设在"剩余输入不可能超过的业务值"。
- 避免在重复结构中使用零尺寸子构造；`Array(n, Pass)` 这类写法应改为 `Padding(n)` 或 `Bytes(n)`。

## 5. 结论

- 有界的情形：元素定长且消耗输入时，`Array`/`PrefixedArray`/`RepeatUntil` 的内存与迭代次数都被"剩余字节数 ÷ 元素大小"天然限制，失败快速（`StreamError`）。
- 无界的情形：元素不消耗输入时，解释执行与编译执行都把攻击者可控的计数直接当作迭代次数，造成与输入大小完全脱钩的 CPU/内存消耗；`RepeatUntil` 叠加永不满足的谓词时是真正的无限循环。
- 编译执行不仅不更安全，反而引入三处错误传播倒退：负数计数静默通过、`discard` 被忽略、`io.read` 短读不报错。
- 修复的关键是在消耗计数之前用"剩余输入量"做 O(1) 预检，并对零尺寸元素重复和零进度迭代直接拒绝。
