# 偏移指针环与惰性递归解析放大

**目标版本**:construct 2.10.70(`construct/version.py`),commit `28c6e57`。

## 0. 结论摘要

1. **环形输入不会被识别为环。** `Pointer._parse`(`construct/core.py:4428`)只是 seek → 递归解析 → seek 回来,`Lazy._parse`(`core.py:5925`)只是记录偏移并返回闭包。全库没有任何已访问偏移集合、深度计数或访问次数预算。终止条件**完全**依赖底层流读取失败(`StreamError`)或 Python 解释器的 `sys.recursionlimit`(默认 1000)抛出的 `RecursionError`。
2. **最小环形输入是 0 字节。** 构造 `Struct("p" / Pointer(0, LazyBound(lambda: d)))` 对 `b""` 解析即无限递归(实测 0.0008s 后 `RecursionError`)。不需要任何攻击者可控的整数字段。
3. **拒绝方式不是库错误,是解释器错误。** `recursionlimit=1000` 时合法递归链最多 **99 个节点**(每节点约 10 个 Python 栈帧),第 100 个节点就抛 `RecursionError`(实测 `exp56`;与按帧推算一致)。因此合法协议与环形输入在默认配置下**共享同一个终止机制**,无法靠异常类型区分。
4. **`RecursionError` 不是 `ConstructError`**(`RecursionError` → `RuntimeError` → `Exception`),但它是 `Exception` 子类,因此会被 `GreedyRange._parse`(`core.py:2613`)与 `Select._parse`/`Select._build`(`core.py:3867`、`3879`)的 `except Exception:` 吞掉。实测副作用是 **livelock + 内存持续增长**:`GreedyRange` 在 2 秒内做了 22 万次解析、RSS 增长 35 MB,20 秒后仍在跑(RSS +338 MB),永不返回。`Union`/`Switch` 的 `_parse` **没有**宽泛 except,`RecursionError` 正常冒泡。
5. **惰性路径不提供任何终止保证。** `Lazy` 的闭包可被反复调用,每次只解析一"层"且没有任何状态,10 万次嵌套调用 0.099 s 完成、不抛异常;`LazyStruct`/`LazyArray` 对固定尺寸字段(`Pointer` 的 `_sizeof` 恒为 0)整字段跳过,所以环在**解析期**根本不触发,只在字段访问时才逐层展开。深度护栏对"逐次调用"的闭包链**无效**(每次 `execute()` 深度归零),只有跨调用的访问预算能拦。
6. **`Pointer` 还是一条"任意偏移放大器",不只是环。** 3 字节/节点的 DAG(两个孩子都指向同一个后继节点)在 48 字节输入下触发了 65,535 次节点解析(0.51 s),60 字节触发 1,048,575 次(10.4 s),66 字节触发 4,194,302 次(36.2 s);访问次数约每节点 ×4,即 `2^n`。这条路不是环、深度也很浅,**不需要 `RecursionError` 就能耗尽 CPU**。
7. **建议的修复是"深度上限 + 访问预算 + `RecursionError` 归一化 + `GreedyRange` 零进度检测"四件套**,并**不要**用"已访问偏移集合"来判环 —— 实测它会误伤**完全有限、零递归**的合法嵌套指针(见第 4.4 节)。需要说明的一条边界:深度上限只覆盖"一次调用内叠起来的递归",`LazyStruct`/`LazyArray` 的逐层字段访问(每次只深入一层)默认拦不住,必须在 `LazyContainer.__getitem__` 处额外接入跨访问计数。

---

## 1. 实现路径阅读

### 1.1 入口与上下文

```
Construct.parse          core.py:391   → parse_stream(BytesIO(data))
Construct.parse_stream   core.py:407   → context = Container(**contextkw); context._params = context
                                       → self._parsereport(stream, context, "(parsing)")
Construct._parsereport   core.py:428   → obj = self._parse(...); 再调用 self.parsed 回调
```

`contextkw` 只作为关键字参数进入**根**上下文。关键事实(实测 `exp41_final_checks.py`):**每个 `Struct`/`Sequence`/`Union` 在 `_parse` 里都新建自己的 `Container`**(`core.py:2234`),该子上下文通过 `_ = 父上下文` 向上链接,但写进子上下文的键**不会**回写到父上下文。层级实测:4 层嵌套有 4 个不同的 `id(context)`,而 `id(context._params)` 和 `id(context._root)` 只有 1 个。

**推论(决定了护栏怎么设)**:任何"计数器放在 context 里"的天真实现**会失效** —— 每深入一层 `Struct` 就换一个新字典,计数被重置。唯一稳定的锚点是 `context._params`(整个解析调用共享同一个对象,实测恒定),护栏状态必须挂在它上面。

### 1.2 `Pointer`:跟随偏移指针

```python
# core.py:4417
def _pointer_seek(self, stream, context, path):
    offset = evaluate(self.offset, context)        # 攻击者控制的整数字段,可来自 Byte/Int16ub/...
    stream = evaluate(self.stream, context) or stream   # 可换成 context 里的任意流对象
    fallback = stream_tell(stream, path)
    if self.relativeOffset:
        stream_seek(stream, offset, 1, path)       # 相对当前位置
    else:
        stream_seek(stream, offset, 2 if offset < 0 else 0, path)   # 负值 = 从 EOF 往前
    return fallback

# core.py:4428
def _parse(self, stream, context, path):
    fallback = self._pointer_seek(stream, context, path)
    obj = self.subcon._parsereport(stream, context, path)
    stream_seek(stream, fallback, 0, path)
    return obj
```

要点:

- **没有任何目标合法性检查**:不校验 `offset` 是否落在已解析区间、是否指向自身、是否与当前栈帧相同。`stream_seek`(`core.py:204`)只把 `seek()` 抛的非 `ConstructError` 转成 `StreamError`。
- **`BytesIO` 的负方向 seek 会被钳制**:`seek(-100, 2)` 在 3 字节流上返回 0(实测),`Pointer(-100).parse(b"abc")` 读出偏移 0 的字节。于是"负偏移"并不总是读越界 —— 它构造了**回到偏移 0 的合法跟随**,这是最小环的另一种形态。
- **失败时不恢复位置**:`_parse` 里 `stream_seek(fallback)` 在子解析之后才执行,若子解析抛异常,位置就留在子解析停下的地方。对单次 `parse()` 影响有限(异常会冒泡到顶层),但被 `GreedyRange`/`Select` 吞掉后会改变后续重试的起点。

### 1.3 三条递归/惰性路径

**(a) 贪心递归 —— `LazyBound`**

```python
# core.py:6242
def _parse(self, stream, context, path):
    sc = self.subconfunc()          # 每次调用都重新取构造实例
    return sc._parsereport(stream, context, path)
```

`LazyBound` 自身不设终止条件。终止必须由**外层数据相关条件**提供,文档给出的正规写法是 `If`(`core.py:3944`):

```python
d = Struct("value" / Byte, "next" / If(this.value > 0, LazyBound(lambda: d)))
```

这是合法递归能在 1000 帧限制下存活的唯一常见写法:**`If` 用数据字段做门,数据为 0 时整棵子树不解析**。但攻击者只要让 `If` 的条件字段与指针目标解耦(`flag` 恒为 1、偏移字段另设),环就不再被 `If` 截断。

**(b) 惰性字段 —— `Lazy`**

```python
# core.py:5925
def _parse(self, stream, context, path):
    offset = stream_tell(stream, path)
    def execute():
        fallback = stream_tell(stream, path)
        stream_seek(stream, offset, 0, path)
        obj = self.subcon._parsereport(stream, context, path)
        stream_seek(stream, fallback, 0, path)
        return obj
    len = self.subcon._actualsize(stream, context, path)   # 这里可能递归/可能抛 SizeofError
    stream_seek(stream, len, 1, path)
    return execute
```

`Lazy` **在解析期只推进 `_actualsize` 那么多**(`Pointer._sizeof` 返回 0,所以 `Lazy(Pointer(...))` 推进 0 字节)。真正的解析推迟到 `execute()`。如果子构造又是 `Lazy` 或 `Pointer`→`LazyBound` 到自身,每次 `execute()` 只展开一层并返回**又一个闭包**:实测连续 100,000 次调用耗时 0.099 s、无异常,调用方可无限进行。这不是"拒绝失败",而是**没有失败**。

**(c) 整字段跳过的惰性容器 —— `LazyStruct` / `LazyArray`**

```python
# LazyStruct._parse core.py:6025
for i,sc in enumerate(self.subcons):
    try:
        offset += sc._actualsize(stream, context, path)   # Pointer._actualsize == _sizeof == 0
        stream_seek(stream, offset, 0, path)
    except SizeofError:
        parseret = sc._parsereport(stream, context, path)
        ...
```

`Pointer` 的 `_sizeof` 恒为 0(`core.py:4440`),`_actualsize` 默认返回 `_sizeof`(`core.py:508`),所以**固定尺寸字段被"跳过"而完全不解析**。于是 `LazyStruct("v"/Byte, "p"/Pointer(0, LazyBound(lambda: LS)))` 对 `b"\x01"` 解析会立刻成功,环只存在于字段访问时:

```python
# LazyContainer.__getitem__ core.py:5959
stream_seek(self._stream, self._offsets[index], 0, self._path)
parseret = self._struct.subcons[index]._parsereport(self._stream, self._context, self._path)
self._values[index] = parseret     # 每个容器各自缓存;不同层是不同容器
```

实测 `o.p is o.p` 为 `True`(同容器内缓存),`o.p is o` 为 `False`,逐层 `x = x.p` 每次返回**新 id 的 LazyContainer** —— 无限可生成对象、内存随访问增长(200,000 个保留闭包 +95 MB)。`LazyArray` 的 `LazyListContainer.__getitem__`(`core.py:6090`)同构。

### 1.4 谁会吞掉 `RecursionError`

| 位置 | 捕获 | 环形输入下的行为(实测) |
|---|---|---|
| `GreedyRange._parse` `core.py:2613` | `except Exception:` | **livelock**:2 s = 22 万次解析、RSS +35 MB;20 s 仍在跑、RSS +338 MB;**永不返回** |
| `Select._parse` `core.py:3865` | `except Exception:` | 吞掉后落到下一个分支;`Select(cyclic, Pass)` 返回 `None`(0.0008 s) |
| `Select._build` `core.py:3883` | `except Exception:` | 同上(仅构建路径) |
| `Union._parse` `core.py:3709` | 无宽泛 except | 正常冒泡 `RecursionError` |
| `Switch._parse` `core.py:4041` | 无宽泛 except(键值查找) | 正常冒泡 |
| `Peek._parse` `core.py:4512` | `except ConstructError:`(不含 `RecursionError`) | 正常冒泡 `RecursionError` |
| `RestreamData`/`Bitwise` 等 | 无 | 正常冒泡 |

`GreedyRange` 的 livelock 机制值得单独说明:它 `for i in itertools.count()` 循环,每次 `fallback = tell()` → 解析 → 失败 → `seek(fallback)`。环在每个重试里都重新走到 `RecursionError`,被 `except Exception` 吞掉、seek 回起点、再来一次。**每轮都是完整的一次 `recursionlimit` 深度递归**,`context._index` 每轮 +1,`obj` 每轮增长。20 s 采样:call 计数约 10 万/秒线性增长,RSS 约 +17 MB/s 线性增长。`discard=True` 只去掉 `obj.append`,循环本身不变。

---

## 2. 最小输入布局

以下全部实测(`exp28_minimal.py`、`exp36_minlayout.py`),默认 `sys.getrecursionlimit()==1000`,结果均为 `RecursionError`。

| # | 构造(示意) | 输入字节数 | 输入 | 说明 |
|---|---|---|---|---|
| 1 | `Struct("p"/Pointer(0, LazyBound(self)))` | **0** | `b""` | 无需任何字段;`Pointer(0)` 回到自身起始偏移 |
| 2 | `Pointer(0, LazyBound(self))`(裸构造) | **0** | `b""` | 连 `Struct` 包装都不需要 |
| 3 | `Struct("s"/Seek(0), "n"/LazyBound(self))` | **0** | `b""` | `Seek` 也能形成环,与 `Pointer` 无关 |
| 4 | `Struct("p"/Pointer(-1, LazyBound(self), relativeOffset=True))` | **1** | `b"\x00"` | 相对 -1:seek → 0 → 再 -1 … |
| 5 | `Struct("v"/Byte, "n"/Pointer(this.v, LazyBound(self)))` | **1** | `b"\x00"` | `v=0` ⇒ 绝对偏移 0 ⇒ 自环 |
| 6 | `Struct("v"/Byte, "n"/Pointer(this.v, LazyBound(self)))` | **2** | `b"\x01\x00"` 或 `b"\x01\x01"` | 2 节点环(i↔1)或自环 |
| 7 | `Struct("p"/Pointer(-1, LazyBound(self)))` | **2** | `b"\x00\x00"` | EOF−1 落回偏移 0 |
| 8 | `Struct("next_off"/Int16ub, "flag"/Byte, "next"/If(this.flag==1, Pointer(this.next_off, LazyBound(self))))` | **6** | `02 00 01 | 00 00 01` (`U16(2)+b"\x01"+U16(0)+b"\x01"`) | 节点 0↔2 环;**`If` 条件与偏移解耦**,`If` 不再提供终止 |
| 9 | 同上 | **9** | `03 00 01 | 06 00 01 | 00 00 01` | 3 节点环 |
| 10 | 同上,`Pointer` 带 `relativeOffset=True` 且固定 +3 | **3/6** | — | 相邻节点互为前驱/后继即可 |

**最小性论证**:布局 1、2、3 证明"零字节输入即可构成环" —— 因为 `Pointer(0)` 的目标偏移是一个**常量 0**,不消费输入。攻击者可控的整数字段(如布局 5、6)只是让环更难被静态检查发现,并非必要条件。

**对照的合法递归布局**(文档 `docs/lazy.rst` 的 lazy-list):

```
节点 = [value:u16] ; value > 0 ⇒ next @ 绝对偏移 value ; value == 0 ⇒ 结束
字节流 = U16(2) U16(4) U16(6) … U16(0)
```

同一批构造、同一批字节,`value` 到 `0` 即正常终止;把最后一个 `U16(0)` 改成指回前面任何偏移,就变成环。**两种输入只差最后一个 2 字节**。

---

## 3. 实测对照:合法 / 环形 / 深度边界

测量环境:CPython 3.12.3,`sys.getrecursionlimit()=1000`,本仓库代码,`threading` + join 超时用于识别无限循环。

### 3.1 合法递归 vs 环形 vs 深度边界

| 输入 | 结果 | 耗时 |
|---|---|---|
| 合法链 n=3(6 B) | OK | 0.00005 s |
| 合法链 n=60(120 B) | OK | 0.0006 s |
| 合法链 n=99(198 B) | OK | 0.0007–0.0009 s |
| **合法链 n=100(200 B)** | **`RecursionError`** | 0.0008–0.0011 s |
| 合法链 n=101 | `RecursionError` | 0.0008 s |
| 环形 0 字节 | `RecursionError` | 0.0004–0.0008 s |
| 环形 1 字节 | `RecursionError` | 0.0005–0.0012 s |
| 环形 2 节点(6 B) | `RecursionError` | 0.0012 s |
| 环形 3 节点(9 B) | `RecursionError` | 0.0009 s |
| 环形 4 节点(12 B),30 s 预算 | `RecursionError` | 0.0009 s |

**关键点**:合法链 n=100 与环形的**失败类型、失败耗时同量级**,调用方无法区分"协议太深"与"攻击者造环"。

### 3.2 深度边界与解释器限制的定量关系

二分搜索合法链的最大可解析节点数(`exp40/exp42`):

| `sys.recursionlimit` | 最大合法节点数 | 每节点栈帧 |
|---|---|---|
| 200 | 19 | 10.53 |
| 500 | 49 | 10.20 |
| 1000 | 99 | 10.10 |
| 2000 | 199 | 10.05 |

即 **每节点约 10 个 CPython 帧**,`max_depth ≈ recursionlimit / 10`。链长超过约 100 就无论如何都会失败。

### 3.3 提高 `recursionlimit` 不能解决问题

子进程实测(`exp34/exp35`,环 1 节点):

| `recursionlimit` | 结果 | 拒绝耗时 |
|---|---|---|
| 20,000 | `RecursionError` | 0.028 s |
| 50,000 | `RecursionError` | 0.103 s |
| 100,000 | `RecursionError` | 0.308 s |
| 200,000 | `RecursionError` | 1.006 s |
| 500,000 | `RecursionError` | 5.174 s |
| 1,000,000 | 超 120 s 未返回 | >120 s |

把上限调高只是把拒绝成本线性推给攻击者,且在高值时逼近 C 栈溢出(CPython 在此范围最终仍以 `RecursionError` 退出,但进程风险与帧开销都不可接受)。

### 3.4 编译路径(`.compile()`)完全一致

生成的源码里 `Pointer` 变成 `parse_pointer(io, offset, func)`(`core.py:4443`),`LazyBound` 变成 `linkedparsers[id(...)](io, this, '(???)')`(`core.py:577-599`)。实测:

| 输入 | 解释执行 | 编译执行 |
|---|---|---|
| 合法链 n=99 | OK | OK |
| 合法链 n=100 | `RecursionError` | `RecursionError` |
| 自环 2 B | `RecursionError` | `RecursionError` |

**编译不改变递归结构**,也不引入任何深度限制 —— 护栏必须同时覆盖两条路径(而 `compile()` 直接复用 `_parse`,所以修 `_parse` 即可覆盖两者)。

### 3.5 宽泛 `except Exception` 的放大效应

| 消费者 | 输入 | 结果 |
|---|---|---|
| `GreedyRange(cyclic, discard=False)` | 2 B | **2 s = 22 万次解析,RSS +35 MB;20 s 未返回,RSS +338 MB** |
| `GreedyRange(cyclic, discard=True)` | 2 B | 同样 livelock(仅少 append) |
| `Select(cyclic, Pass)` | 2 B | OK,返回 `None`(静默丢弃环) |
| `Union(cyclic)` | 1 B | `RecursionError` 冒泡 |
| `Peek(cyclic)` | 2 B | `RecursionError` 冒泡(只捕 `ConstructError`) |

### 3.6 惰性路径

| 操作 | 结果 | 耗时 |
|---|---|---|
| `Lazy(Pointer(0, LB self)).parse(b"")` | OK,返回闭包 | 0.00001 s |
| 连续调用该闭包 10,000 / 100,000 次 | OK,无异常 | 0.011 s / 0.099 s |
| 保留 200,000 个闭包 | RSS +95 MB | — |
| `LazyStruct("v"/Byte, "p"/Pointer(0, LB self)).parse(b"\x01")` | OK(字段被跳过) | 0.00005 s |
| 同上,`.p` 访问 | OK,返回 `LazyContainer` | 0.00004 s |
| 逐层 `.p.p.p…` | 每层新对象,可无限 | — |
| `LazyArray(3, Pointer(0, Byte))[0]` | OK(`Pointer` 是固定尺寸,被跳过) | 0.00005 s |

### 3.7 无环但是"放大"的输入(DAG)

3 字节/节点,节点含 2 个偏移,两个孩子都指向同一个后继(合法 DAG,不是环,`If` 条件恒 1):

| 节点数 | 字节数 | 结果 | 耗时 | 节点解析次数 | 放大率(次/字节) |
|---|---|---|---|---|---|
| 10 | 30 | OK | 0.025 s | 1,023 | 34× |
| 12 | 36 | OK | 0.045 s | 4,095 | 114× |
| 14 | 42 | OK | 0.138 s | 16,383 | 390× |
| 16 | 48 | OK | 0.51 s | 65,535 | 1,365× |
| 18 | 54 | OK | 1.87 s | 262,143 | 4,854× |
| 20 | 60 | OK | **10.4 s** | **1,048,575** | **17,476×** |
| 22 | 66 | OK | **36.2 s** | **4,194,302** | **63,550×** |

**这不是环,不是递归深度问题** —— 深度只有 22,完全在 `recursionlimit` 内。它是 `2^n` 的重复解析:节点每 +1(字节 +3),访问次数约 ×4。每 6 字节耗时约 ×3.5,66 字节 36 秒;78 字节(n=26,约 6,700 万次)推算约 10 分钟。这条路径**无法**被"深度上限"或"环检测"覆盖,必须用访问次数预算。

> 注意:这里的"DAG 节点数"是**构造上**的节点数(每节点 3 字节),与"解析访问次数"是两回事 —— 后者因重复解析而指数级高于前者。下节的预算用的也是**解析访问次数**。

---

## 4. 建议的防护(保持合法协议兼容)

四条互补,前两条是主修:

### 4.1 深度上限(depth limit)—— 覆盖环,成本最低

在 `Pointer._parse`(以及 `Seek`/`Lazy` 若非 Pointer 起环)进入时在**共享的 `context._params`** 上 `depth += 1`,`finally` 里 `-= 1`,超过上限抛 `ConstructError`。

**为什么必须挂在 `_params`**:每个 `Struct` 新建 context(§1.1),任何"本层 context 计数器"都会在下一层被重置。`id(context._params)` 在整个解析里恒定(实测 4 层嵌套、1 个 id)。

**上限必须低于 `recursionlimit/10`**(每节点约 10 帧,§3.2):深度 200 时环仍先撞 `RecursionError`;深度 64 时稳定抛 `ConstructError`(`exp40`)。实测合法链的精确可解析上限(`exp56_boundary.py`):

| 深度上限 D | 合法链最大 n | 首个失败 n | 失败来源 |
|---|---|---|---|
| 32 | 33 | 34 | 深度护栏(D+1) |
| 64 | 65 | 66 | 深度护栏(D+1) |
| 100 | 90 | 91 | **解释器**(`recursionlimit/10≈99`,护栏还没到) |

- 上限 32:环 `ConstructError`,但**误伤**合法链 n≥34(这类输入原本可正常解析到 n=99);
- 上限 64:环 `ConstructError`,合法链 n≤65 通过;n=66..99 原本可解析却被拒 —— 这是**唯一的兼容性代价**,需在文档声明或调高;
- 上限 100:护栏形同虚设(n=91 起由解释器先失败),**不推荐**。

**因此推荐默认 64 时须明确**:它把"原本能解析到 99 层"的合法输入收窄到 65 层。若业务协议确实更深,应显式调高**护栏上限**,并同时把 `sys.setrecursionlimit` 提到 `10×D + 余量`(例如 D=256 时 `recursionlimit≥3000`);两者必须配对,否则护栏上限高于解释器边界就退化回 `RecursionError`。

**另一处相关但需单独说明的行为**:链式集合(§4.4)与深度上限都**不**覆盖"每次只深入一层、但可被无限次调用"的 `LazyStruct` 字段访问(实测 200 次无错误);那条路径只能在 `LazyContainer.__getitem__` 处加跨访问计数。

**推荐:默认 64,可配置。** 它的取舍是:环稳定变成 `ConstructError`,且合法链 n≤65 全部通过;代价是原本能解析到 n=99 的深协议会被收窄到 65(见上表),若业务需要更深则显式调高上限并同步 `sys.setrecursionlimit`(文档须写明 `recursionlimit ≥ 10×D + 余量` 的关系)。合法性与旧行为的另一处差别是错误类型:从"`RecursionError`(非 ConstructError,且可能被 `GreedyRange` 吞掉)"变成"`ConstructError`",协议语义不变。

### 4.2 访问次数预算(visit budget)—— 覆盖指数放大

同一个 `_params` 上维护 `visits`,每次 `Pointer` 进入 +1,超上限抛 `ConstructError`。深度上限对 DAG 无效(§3.7 的深度只有 20),访问预算才有效。

实测(`exp40`,预算 = N):

| 预算 | DAG 20 节点(60 B) | DAG 16 节点(48 B) | 合法 DAG 3 节点 |
|---|---|---|---|
| 1,000 | `ConstructError` 0.0085 s | `ConstructError` 0.0078 s | OK |
| 10,000 | `ConstructError` 0.075 s | `ConstructError` 0.070 s | OK |
| 100,000 | `ConstructError` 0.83 s | OK 0.48 s | OK |

**推荐:默认 10,000**(合法解析里 `Pointer` 通常只有个位数到几十次,10,000 有充裕余量),或按"输入长度 × 常数"自适应(例如 `max(1000, 16 * len)`)。关键是要有**上界**,上界多少由业务选择。**该预算还兼管 `Lazy` 闭包链**:`Lazy` 的逐次 `execute()` 深度不累积,深度上限无效,只有访问预算能拦住(实测 10,000 次后抛错,`exp49_lazyguard.py`)。

### 4.3 `RecursionError` 归一化(+ 阻止宽泛 `except Exception` 吞它)

`RecursionError` 不是 `ConstructError`,但作为 `Exception` 子类会被 `GreedyRange` 与 `Select`(parse+build)的 `except Exception:` 吞掉。修法:

1. 在 `Construct.parse_stream`(`core.py:407`)加 `except RecursionError: raise ConstructError("input recursion too deep (possible pointer cycle)", path=...)` —— 让 API 边界只暴露 `ConstructError`(库契约本身就要求如此,`core.py:395`)。
2. 在各处宽泛 `except Exception:` 之前**先 `except RecursionError: raise`**,或改成 `except ConstructError:`(语义更精确)。尤其 `GreedyRange._parse`(`core.py:2613`)与 `Select._parse`(`core.py:3865`)。
3. `GreedyRange` 另加**零进度检测**:每轮记住上一轮 `tell()`,若本轮 `tell()` 与本轮起点相同(子构造未消费任何字节),立即 `raise ConstructError`,而不是 `seek` 后重试。这条独立于环:它同时也修掉了经典的 `GreedyRange(Pass)` 死循环。

注意:`GreedyRange(Pass)` 与 `GreedyRange(Struct(...零消费...))` 本就是"无穷循环 + 内存增长"的**既存缺陷**(实测 `GreedyRange(Pass).parse(b"")` 4 s 不返回),与环无关,应在同一处修掉。

### 4.4 已访问偏移集合 —— **不推荐作主判据**

链式集合(只在当前递归链上记录 `(stream_id, target_offset)`,退出时移除)**能**精确抓住环(实测:2 节点环 → `ConstructError`;合法 3 节点链 → OK;两个兄弟指针指向同一偏移 → OK)。但它有**两个**实测到的误伤:

- **无递归的嵌套重访**(最直接的误伤):`Struct("outer"/Pointer(0, Struct("a"/Byte, "inner"/Pointer(0, Byte))), "tail"/Byte)` 对 `b"\x2a\x2b"` 是完全有限、零递归的合法解析(结果 `Container(outer=Container(a=42, inner=42), tail=42)`),但内层指针在**外层指针仍处于活动链上**时又指向偏移 0,链式集合直接判环(`ConstructError: pointer cycle at offset 0`,实测 `exp51_falsepos.py`)。这说明"同一偏移在祖先链上被重访"**完全可以合法**。
- **数据驱动的递减重访**:若协议用递减计数(或任何库不可见的变形状态)逐层读同一区域,链式集合同样误报。注意:如果构造里没有任何数据驱动的终止条件(纯静态构造),同一偏移读到的是**同样字节**,那它其实已经是真环 —— 这类输入被拒是正确的;真正需要守护的是上一类"有限但有重访"的合法构造。

此外,全局集合(整次解析只记录一次、不 pop)在合法"两个指针指向同一共享表"上也误报(实测),并把合法 DAG 的共享子树全部判环。

**结论**:`(流,偏移)` 不是环的正确判据 —— 环的正确判据需要 `(流, 偏移, 未变的数据状态)` 三者,而"数据状态是否变化"库无法观察(指针不消费偏移,`Pointer._sizeof` 恒为 0)。因此**用深度上限**(它天然对应"栈帧重复")比用偏移集合更兼容合法协议。若仍想加偏移集合,建议只作为**诊断信息**(抛深度错误时附带"重复偏移=…"),不作拒绝条件;且必须是链式(退出即移除),绝不用全局集合。

### 4.5 兼容性矩阵(护栏开启后)

| 场景 | 现状 | 护栏后 | 兼容? |
|---|---|---|---|
| 合法链 n≤65 | OK | OK | ✅ 完全一致 |
| 合法链 66≤n≤99(旧行为 OK) | OK | 默认 D=64 下被拒 | ⚠️ 唯一兼容性代价;需调高上限 + 同步 recursionlimit |
| 合法链 n≥100 | `RecursionError` | `ConstructError`(更可诊断) | ✅ 契约更好 |
| 任意环 | `RecursionError` / livelock | `ConstructError` | ✅ 修复 |
| 合法 DAG 访问 <预算 | OK | OK | ✅ |
| 合法 DAG 访问 >预算 | OK(慢) | `ConstructError`(可配置) | ⚠️ 需按业务调预算 |
| `Lazy` 闭包链(连续 `execute()`) | 可无限(10 万次 0.099 s) | 深度不累积,**由访问预算拦住**(实测 10,000 次后 `visits 10001`);深度上限单独无效 | ⚠️ 需预算 |
| `LazyStruct`/`LazyArray` 逐层字段访问 | 可无限(每层新对象) | **默认护栏拦不住**:每次 `.p` 只深入一层(深度=1)且每次仅 +1 访问,实测 200 次访问无错误;需在 `LazyContainer.__getitem__`/`LazyListContainer.__getitem__` 里**跨访问**累计访问计数才有效 | ❌ 需额外接入点 |

补充(实测 `exp49`/`exp52`/`exp53`):
- `Lazy` 闭包链:**深度**计数每次都回到 0(`execute()` 内层解析完成后 `finally` 归零),故深度上限无效;只有**访问预算**能拦住。
- `LazyStruct` 逐层访问更隐蔽:`LazyContainer.__getitem__`(`core.py:5959`)用**构造时保存的** context 重新 `_parsereport`,每次访问都是独立一次、只深入一层;实测连续 200 次 `x = x.p` **不报错**。要拦住它,必须把访问计数挂在 `LazyContainer` 的 `_context._params` 上(该 context 在容器生命周期内恒定),而不能只依赖 `Pointer` 的进入/退出计数。
- 结论:深度上限只覆盖"一次调用内叠起来的递归";`Lazy`/`LazyStruct` 的"每次调用展开一层"必须靠**跨调用累计的访问预算**,且 `LazyStruct` 需要显式接入点。

### 4.6 参考实现(已验证,仅示意)

```python
class GuardPointer(Pointer):
    MAXDEPTH = 64          # 必须 ≤ recursionlimit/10 左右
    MAXVISITS = 10000
    def _parse(self, stream, context, path):
        root = context._params                 # 全解析唯一的稳定锚点
        st = getattr(root, "_guard", None)
        if st is None:
            st = root._guard = [0, 0]          # [depth, visits]
        st[0] += 1; st[1] += 1
        try:
            if st[0] > self.MAXDEPTH:
                raise ConstructError("pointer depth %d exceeds %d" % (st[0], self.MAXDEPTH), path=path)
            if st[1] > self.MAXVISITS:
                raise ConstructError("pointer visits %d exceeds %d" % (st[1], self.MAXVISITS), path=path)
            return super()._parse(stream, context, path)
        finally:
            st[0] -= 1
```

实测效果(`exp39`/`exp40`):
- 1 字节环 → `ConstructError`(`depth 65`,D=64);
- 合法链 n=60 → OK;边界精确为 n≤65 OK、n≥66 `ConstructError`(`exp56`);
- DAG 20 节点(60 B)→ `ConstructError`(预算 100,000 时 `visits 100001`,0.83 s;预算 10,000 时 0.075 s);
- 开销(合法链 n=60,2000 次交错 A/B,`exp40`):**+9.9%**(早先粗测因预热缺失报 +29%~74%,以交错测量为准)。

⚠️ 接入时要处理的细节:
1. `_params` 上的 `_guard` 在**一次 `parse()` 调用内**共享(每次 `parse` 新建根 context,自然重置);若同一根 context 被复用(如多次 `parse_stream` 传同一个 context),需在 `parse_stream` 入口显式重置。
2. 本护卫**只挂在 `Pointer` 上**。非指针成环的路径 —— `Seek(0)`+`LazyBound`(§2 表格 #3)、以及 `Lazy`/`LazyStruct` 的逐层字段访问(§4.5)—— 不在其覆盖内,需分别接入(前者可复用同样的深度计数,后者需在 `LazyContainer.__getitem__` 加跨访问计数)。
3. DAG 放大即使**深度很小**也会触发:预算必须在每次 `Pointer` 进入时 +1,不能只在深度变化时计。

---

## 5. 回归测试清单

建议加入 `tests/test_core.py`(风格沿用现有 `raises(...) == XxxError` 与 `common(...)`)。

**A. 拒绝(护栏前应全部为 `RecursionError` / 超时;护栏后应为 `ConstructError`)**

1. `test_zero_byte_pointer_cycle`: `Struct("p"/Pointer(0, LazyBound(lambda: d)))` 对 `b""` → `ConstructError`,且耗时 < 50 ms。
2. `test_one_byte_relative_cycle`: `Struct("p"/Pointer(-1, LB, relativeOffset=True))` 对 `b"\x00"` → `ConstructError`。
3. `test_two_byte_self_offset`: `Struct("v"/Byte,"n"/Pointer(this.v, LB))` 对 `b"\x00"` → `ConstructError`。
4. `test_two_node_ring`: 同上,`b"\x01\x01"` / `b"\x02\x00\x00"`(u8 偏移环)→ `ConstructError`。
5. `test_three_node_ring_if_decoupled`: 6/9 字节、`If` 条件与偏移解耦 → `ConstructError`。
6. `test_seek_self_cycle`: `Struct("s"/Seek(0),"n"/LazyBound(self))` 对 `b""` → `ConstructError`。
7. `test_negative_absolute_clamp_cycle`: `Pointer(-100, …)` 在短流上被钳到 0 → `ConstructError`(守卫不必区分,关键是**不挂起**)。
8. `test_compiled_cycles`: 对 1–7 各构造 `.compile()` 后重复断言(编译路径不得绕过护栏)。
9. `test_cycle_is_construct_error`: `isinstance(e, ConstructError)`,且 `e.path` 非 None。
10. `test_no_exception_escapes_non_construct`: 所有拒绝路径不得抛 `RecursionError` 给外部(`parse()` 契约)。

**B. 无限循环 / 超大工作量(必须用超时或访问计数,不能只断言异常)**

11. `test_greedyrange_cycle_no_livelock`: `GreedyRange(cyclic_struct, discard=False)` 对 2 字节 → 在 ≤1 s 内抛 `ConstructError`(现状 20 s 未返回)。
12. `test_greedyrange_zero_progress`: `GreedyRange(Pass).parse(b"")` → 立即 `ConstructError`(既存缺陷)。
13. `test_select_cycle_not_silently_none`: `Select(cyclic, Pass)` 返回 `None` 还是抛错?**先确定期望**;若保持吞掉,至少断言耗时上界与访问计数上界。建议改为抛。
14. `test_exponential_dag_budget`: 20 节点 DAG(60 B)→ `ConstructError`,耗时 ≤ 1 s(现状 10.4 s),并断言访问次数 ≤ 预算。
15. `test_dag_growth_is_bounded`: 对 n=12/14/16 断言访问次数 ≤ `k·n`,而不是 `~2^n`。

**C. 惰性路径**

16. `test_lazy_thunk_no_unbounded_growth`: `Lazy(Pointer(0, LB self))` 的闭包链连续调用 N 次后由**访问预算**抛 `ConstructError`(实测 10,000 次触发,`exp49_lazyguard.py`);断言"深度上限单独不够"(即若只开深度护栏则应记录为已知缺口)。
17. `test_lazystruct_pointer_skipped_then_guarded`: `LazyStruct` 解析成功(环在解析期不触发),重复访问同容器返回同一对象。**注意**:`Pointer` 护栏默认**不**拦逐层 `.p`(实测 200 次无错误);若引入 `LazyContainer` 级计数,断言 N 次后抛 `ConstructError`;若不引入,则把它记为**已知缺口**,并断言每次访问耗时有上界。
18. `test_lazyarray_pointer_skipped_then_guarded`: 同上(`LazyListContainer.__getitem__`)。

**D. 合法输入不得回归(最重要的一组)**

19. `test_legal_lazy_list_n3`: 文档样例 3 节点 → 与原结果逐字段相等。
20. `test_legal_lazy_list_n60`: 合法链 60 节点 → OK(默认深度 64 时)。
21. `test_legal_chain_boundary`: 断言边界被有意改变:旧行为 n≤99 OK、n≥100 `RecursionError`;新行为(默认 D=64)n≤65 OK、n≥66 `ConstructError`(实测 `exp56_boundary.py`)。参数化记录 D=32/64/100 三种上限下的边界,防止将来改默认值时无声漂移。
21b. `test_depth_limit_pairs_with_recursionlimit`: 设 D=128 且 `sys.setrecursionlimit(2000)` 时合法链 n=120 → OK;设 D=128 但保持默认 limit=1000 时合法链 n=120 → `RecursionError`(证明两者必须配对)。
22. `test_legal_sibling_pointer_same_offset`: 两个兄弟 `Pointer(4, Byte)` 指向同一偏移 → OK(证明没有误用全局偏移集合)。
23. `test_legal_shared_subtree`: `Array(3, Struct("off"/Byte,"val"/Pointer(this.off, Byte)))` 指向同一共享表 → OK。
24. `test_legal_nested_pointer_same_offset`: `Struct("outer"/Pointer(0, Struct("a"/Byte,"inner"/Pointer(0, Byte))), "tail"/Byte)` 对 `b"\x2a\x2b"` → OK,结果 `Container(outer=Container(a=42,inner=42), tail=42)`(**专门守护 §4.4 的链式集合误伤**;若实现里加了偏移集合,这条必须通过)。
25. `test_legal_union_reparse`: `Union` 从同一 fallback 解析两个分支 → OK(现状即如此)。
26. `test_legal_deep_but_within_limit`: 深度上限可配置;`GuardPointer(MAXDEPTH=256)` + `sys.setrecursionlimit(3000)` 时合法链 n=200 → OK(证明上限可调而不撞解释器边界)。

**E. 指标与契约**

27. `test_rejection_latency`: 500 次环拒绝累计 < 0.5 s(实测守卫后约 0.426 ms/次 vs 未守卫 0.736 ms/次)。
28. `test_overhead_bounded`: 合法链 n=60 的 2000 次交错基准,守卫开销 < 20%(实测 +9.9%)。
29. `test_error_message_mentions_cycle_or_depth`: `ConstructError` 文本含 `pointer depth`/`pointer visits`/`cycle`,便于运维定位。
30. `test_parsed_hook_not_double_fired`: 护栏抛错时不得触发 `parsed` 回调(`_parsereport` 在 `_parse` 之后才回调,天然满足;加断言防回归)。

---

## 6. 报告与复现

- 所有数字来自 `/srv/fb2/fangzhengmei/0053-construct-6-d6358980` 之外的临时目录 `/tmp/cycle-exp/`(`exp1_cycle.py` … `exp48_checks.py`,未放入仓库),解释器 CPython 3.12.3。
- 基准用 `threading.Thread(..., daemon=True).join(timeout)` 判定"未返回",用 `/proc/self/statm` 采样 RSS;高 `recursionlimit` 用子进程隔离(避免污染主进程)。
- 环形输入一律以"是否在超时内返回 + 抛出类型"两种维度记录;仅断言异常类型会漏掉 `GreedyRange` 这类 livelock(它不抛异常,只是不返回)。
- 本文引用的行号对应 `28c6e57` 的 `construct/core.py`(6447 行)。

## 7. 一句话结论

`Pointer`+`LazyBound`/`Lazy` 的组合没有任何环检测或深度/访问上限,终止完全依赖 `StreamError` 与解释器 `RecursionError`;0 字节输入即可构成环,而合法深度与环在默认 `recursionlimit` 下几乎无法用异常类型区分。建议以"`_params` 锚定的**深度上限(默认 64)+ 访问预算(默认 10,000)**"为主,配合"`RecursionError` → `ConstructError` 归一化"与"`GreedyRange` 零进度检测";不要以已访问偏移集合作判据(它会误伤合法的同偏移重访与共享子树);`LazyStruct` 的逐层字段访问还需额外接入跨访问计数。
