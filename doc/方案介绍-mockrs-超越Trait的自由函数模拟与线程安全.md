# `mockrs` — 超越 Trait 的自由函数模拟与线程安全

摘要

mockrs 通过在运行时修改函数入口机器码并结合信号处理与线程本地存储（TLS），实现对任意函数（自由函数、具体方法、FFI 函数）的精确模拟，并在多线程环境中提供严格的线程隔离。相较传统基于 Trait 的模拟库，mockrs 不需要对生产代码进行接口化重构，适合集成测试与复杂边界场景。本文系统阐述问题背景、设计目标、架构与关键方案、实现细节、跨架构差异、工程化与测试、效果评估以及局限与展望。

---

## 1. 引言

### 1.1 背景与动机

在 Rust 生态中，测试是构建可靠软件的基石。传统模拟库（如 mockall）功能强大，但几乎都基于 Trait 工作：开发者需要先定义 Trait，再生成模拟实现并通过依赖注入在测试时使用。这一模式鼓励面向接口编程，但也带来如下局限：
- 无法模拟自由函数（fn my_func(...)）
- 无法模拟外部依赖的具体实现（未通过 Trait 暴露）
- 为可测试性引入不必要的设计约束（重构成本高）
- 难以处理 FFI 函数

### 1.2 问题陈述

目标是在不修改被测代码设计的前提下，能够在运行时对任意函数进行拦截与替换；并且在多线程场景中，确保仅对指定线程生效，其他线程无感。

### 1.3 目标与非目标

- 目标：
  - 任意函数模拟（自由函数、具体方法、FFI）
  - 线程隔离（仅影响当前线程）
  - 易用性（提供 mock! 宏）
  - 跨架构支持（x86_64 与 aarch64）
  - RAII（作用域结束自动恢复）
- 非目标：
  - 性能极致优化的热点路径替换（每次调用都会引发信号）

### 1.4 快速上手

- 依赖与导入：use mockrs::mock;
- 基本用法：传入原函数与模拟函数的名称，返回的 Mocker 在当前线程内生效，离开作用域自动恢复。

示例：
```rust
use mockrs::mock;

fn add(a: i64, b: i64) -> i64 { a + b }
fn mock_add(_a: i64, _b: i64) -> i64 { 100 }

fn main() {
    assert_eq!(add(1, 2), 3);

    // 在当前线程内，将 add 替换为 mock_add
    let mocker = mock!(add, mock_add);
    assert_eq!(add(1, 2), 100);

    // 作用域结束或手动 drop 后恢复
    drop(mocker);
    assert_eq!(add(1, 2), 3);
}
```

- 线程隔离：mock! 仅对创建它的线程生效。其他线程调用原函数不受影响。
- 小贴士：
  - 若函数被强内联，测试中可临时加 #[inline(never)] 避免内联，确保有独立入口可挂钩。
  - 模拟函数的签名需与原函数一致（参数与返回值一致）。

---

## 2. 核心思路与顶层模型

### 2.1 核心思路

mockrs 不在类型系统层面做替换，而是在运行时直接对函数入口的机器码做最小篡改：将第一条指令替换为陷阱指令（x86_64 上的 int3，aarch64 上的 brk）。任何线程执行到此处都会触发 SIGTRAP，由全局信号处理器接管执行流；随后根据“线程本地模拟表（TLS）”决定是跳转到模拟函数，还是执行被备份到“蹦床（Trampoline/Trunk）”中的原始指令并精确恢复。

### 2.2 顶层模型

- 全局提问：陷阱指令 + 全局信号处理器捕捉 SIGTRAP
- 线程本地回答：TLS 中的 G_THREAD_REPLACE_TABLE 决定本线程是否模拟以及跳转目标
- 蹦床（Trampoline；与实现中的变量命名保持一致，文中也称 Trunk）：备份原始指令（必要时重写以修复 PC 相对寻址），并在必要时带跳回序列
- RAII：Mocker 生命周期结束时撤销当前线程的模拟记录

顶层模型示意图：
```plantuml
@startuml
title 顶层模型执行路径

skinparam rectangle {
    roundCorner 20
}

actor "调用线程" as Thread
rectangle "函数 F 入口\n(陷阱: int3/brk)" as Entry
database "全局信号处理器" as Handler
database "TLS 模拟表\n(G_THREAD_REPLACE_TABLE)" as TLS
rectangle "模拟函数 M" as M
rectangle "蹦床 (Trunk)\n原始指令 + 跳回" as Trunk

Thread --> Entry : 调用 F
Entry --> Handler : 触发 SIGTRAP
Handler --> TLS : 查询当前线程的模拟表
TLS --> Handler : 命中/未命中
Handler --> M : 命中 -> 跳转执行 M
Handler --> Trunk : 未命中 -> 执行原始指令
Trunk --> Thread : 跳回 F+len 继续

note bottom
RAII：Mocker 离开作用域自动\n撤销 TLS 中的模拟记录
end note

@enduml
```

### 2.3 设计原则

- 最小侵入：仅修改函数入口处字节
- 可证恢复：未模拟线程路径具备确定性和可验证的恢复流程
- 架构适配：针对 x86_64 与 aarch64 的指令集特性分别采用最稳健机制
- 工程可用：提供 CI 与 aarch64 交叉测试保障

### 2.4 与 Trait 模拟的差异对比

| 维度 | Trait 模拟 | mockrs |
| --- | --- | --- |
| 改造成本 | 常需为可测试性重构生产代码（抽象接口、依赖注入）。 | 直接作用于已存在的自由函数/具体实现，无需为测试重构设计。 |
| 可模拟对象 | 以接口为中心，难以覆盖自由函数与部分 FFI。 | 自由函数、具体方法、FFI 均可（前提是有可寻址入口）。 |
| 线程隔离 | 通常为进程级替换，难以自然隔离线程。 | TLS 驱动的线程级生效，天然支持并发测试的相互独立。 |
| API 复杂度 | 需要定义/实现 Trait，配置期望与行为。 | 一个 mock! 宏即可完成替换，RAII 自动恢复。 |
| 典型场景 | 单元测试、面向接口的业务逻辑隔离。 | 集成测试、边界条件/自由函数/FFI/系统调用包装等难以接口化的路径。 |

### 2.5 具体局限性示例：为什么仅有 Trait Mock 与非线程独立 Mock 不够

#### 2.5.1 基于 Trait 的 Mock 的局限性（示例）

- 场景 A：自由函数/FFI 难以通过接口注入
  - 现状：许多现存代码直接调用自由函数或 FFI，例如 std::fs::read_to_string、libc::gettimeofday/clock_gettime、自定义 util::now() 等。
  - 典型业务代码：
    ```rust
    mod lib {
        pub fn read_token() -> String {
            std::fs::read_to_string("/secure/token").unwrap()
        }
    }

    pub fn business() -> bool {
        let t = lib::read_token();
        t.trim() == "prod"
    }
    ```
  - 若用 Trait Mock，需要为可测试性重写设计，引入接口与依赖注入：
    ```rust
    pub trait TokenReader {
        fn read_token(&self) -> String;
    }

    pub struct Real;
    impl TokenReader for Real {
        fn read_token(&self) -> String {
            std::fs::read_to_string("/secure/token").unwrap()
        }
    }

    pub fn business<R: TokenReader>(r: &R) -> bool {
        let t = r.read_token();
        t.trim() == "prod"
    }
    ```
  - 问题：
    - 扩散式改动：business 的签名变化会沿调用栈层层传递，影响大量文件与模块。
    - 第三方/FFI 不可控：对于外部 crate 或 C 接口，无法强制其改为 Trait 暴露，更无法修改其调用点。
    - API 稳定性受损：为了测试引入的 Trait/泛型约束，改变了对外 API 与类型边界，增加维护复杂度。
    - 设计被测试绑架：把“可测试性”要求强加到生产代码，违背最小侵入原则。

- 场景 B：静态/关联函数、具体实现难以抽象
  - 例如某具体类型的关联函数 T::connect() 或全局初始化函数 init_logging()，若非预先以 Trait 抽象，事后很难安全地改为依赖注入；即便能改，也需要跨层接口调整与生命周期/Send/Sync 约束处理，成本与风险都很高。

- mockrs 的解法：
  - 直接在运行时替换这些自由函数/具体实现的入口，无需改动被测代码设计；测试结束自动恢复，保持生产代码纯净。

#### 2.5.2 非线程独立的 Mock 的局限性（以 mockcpp 为例）

- 背景：传统 C/C++ 打桩方案（以 mockcpp 等为代表）常通过对全局符号的进程级替换来实现自由函数模拟。这类替换通常是“全局生效”的：一旦设桩，整个进程内所有线程都会看到被替换后的行为。

- 并发下的典型问题（伪代码示例，展示现象而非特定 API）：
  ```cpp
  // 真实实现：f() 返回 0
  int f();

  // 线程 A 希望把 f() 桩成返回 1
  void threadA() {
      set_global_stub(f, [](){ return 1; }); // 进程级生效
      EXPECT_EQ(f(), 1);                      // 通过
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      clear_global_stub(f);
  }

  // 线程 B 希望调用真实 f()
  void threadB() {
      // 期望：真实行为
      EXPECT_EQ(f(), 0);                      // 可能失败：被 A 的全局桩污染
  }

  int main() {
      std::thread A(threadA);
      std::thread B(threadB);
      A.join(); B.join();
  }
  ```
  - 现象：
    - 污染：线程 B 在 A 的桩有效期间也会命中桩，预期与实际不一致。
    - 竞态：若 B 在 A 清桩的同时执行 f()，可能出现未定义行为或间歇性失败。
    - 难以并行：为了避免互相污染，只能串行化测试或使用复杂同步，降低测试吞吐量。

- mockcpp 一类“进程级打桩”方案的局限性总结：
  - 缺乏线程隔离：替换范围是进程级而非线程级，不能满足“同进程多场景并行”的测试需求。
  - 全局状态竞争：桩的安装/卸载与被测代码的多线程调用相互交织，容易产生数据竞争与时序问题。
  - 复杂的用例下难以维护：需要额外同步与测试编排来规避污染，成本高且脆弱。

- mockrs 的对照优势：
  - 替换记录保存在 TLS，仅对创建桩的线程生效；其他线程走“蹦床 + 恢复”路径，始终执行真实实现。
  - 无需跨线程同步与封锁即可并行跑不同场景的测试；RAII 生命周期自动恢复，降低误用概率。

---

## 3. Linux 信号处理流程与寄存器修改可行性

利用 Linux 的信号处理机制（sigaction + SA_SIGINFO），用户态信号处理器可在接收 SIGTRAP 时直接读取并修改 ucontext_t 中保存的寄存器快照（如 x86_64 的 RIP/EFLAGS、aarch64 的 PC/X 寄存器）。当信号处理器返回时，内核依据该上下文恢复用户态寄存器，因而“修改后的寄存器值立即生效”，从而实现执行流重定向。这一机制是 mockrs 基于陷阱指令在用户态完成“跳转到模拟函数”或“切入蹦床”的可行性根基。

信号处理总流程（从陷阱到恢复）：
```plantuml
@startuml
title Linux 信号处理流程（从陷阱到寄存器修改再继续执行）

start
:用户线程执行函数 F 的入口;
note right: 入口已被替换为 int3 (x86_64) / brk (aarch64)

:执行陷阱指令 -> 触发同步异常;
:CPU 进入内核态，内核准备信号交付;
note right: 内核构造 sigframe，保存通用寄存器到 ucontext_t/ mcontext_t

:内核将控制权转交给用户态信号处理器 (SA_SIGINFO);
:handle_trap_signal(int sig, siginfo_t*, void* uctx) 被调用;

partition "用户态信号处理器" {
  if (TLS 中命中模拟?) then (是)
    :读取 ucontext;
    :将 IP/RIP/PC 修改为“模拟函数 M”的地址;
    :可按需调整栈/寄存器（通常无需）;
  else (否)
    :读取 ucontext;
    :x86_64: 设置 EFLAGS.TF 进入单步; 将 RIP 指向“蹦床”指令处;
    :aarch64: 将 PC 指向“蹦床”地址（蹦床自带跳回/跳转逻辑）;
  endif
}

:信号处理器返回;
:内核依据（可能已被修改的）ucontext 恢复用户态寄存器;
:用户态从新的 RIP/PC 继续执行（模拟函数或蹦床）;
stop

@enduml
```

关键事实（可行性证明）：
- 用户可写的寄存器上下文：使用 sigaction 注册 SA_SIGINFO 处理器后，第三个参数为 void*，在 glibc 下可转为 ucontext_t*。通过 uc_mcontext 可直接读写通用寄存器与标志位：
  - x86_64：如 gregs[REG_RIP]、gregs[REG_EFL]（EFLAGS），可将 RIP 改为模拟函数地址，或设置 TF 标志位实现单步。
  - aarch64：如 uc_mcontext.pc、uc_mcontext.regs[Xn]，可将 PC 改为蹦床/模拟函数地址；按需使用 X17 作为跳转寄存器。
- 修改当次返回点：信号处理器返回后，内核按 sigframe 恢复寄存器；因此“在处理器返回用户态前修改寄存器”即可无 syscalls 地改变后续执行流，确保低开销与确定性。
- 线程隔离天然成立：信号由触发陷阱的“当前线程”接收与处理，结合 TLS 决策，仅影响当前线程；其他线程即使执行同一函数，也会独立经由各自的 TLS 与处理器路径。
- 调试辅助能力：x86_64 可通过写 EFLAGS.TF 进入单步，精确控制“仅执行蹦床中的一条指令”，第二次 SIGTRAP 再进行恢复/写回抑制；aarch64 借助定长指令与保守的“绝对跳转/跳回”序列避免对单步的依赖。
- 工程建议：
  - 使用 sigaction(..., SA_SIGINFO | SA_RESTART | SA_ONSTACK, ...) 提升健壮性；可在高栈消耗场景配置 sigaltstack 作为信号栈。
  - 仅在测试/开发环境使用该机制（涉及 RWX 与自修改代码）；aarch64 需在写入后执行 dsb sy + ic ivau + isb 刷新 I-Cache。

---

## 4. 架构与执行流程总览

### 4.1 高阶架构图

```plantuml
@startuml
title mockrs 方案高阶架构图

skinparam rectangle {
    roundCorner 25
}
skinparam database {
    roundCorner 25
}

package "用户代码" {
    [线程 A]
    [线程 B]
}

package "共享内存空间" {
    rectangle "函数 F 的代码" as FuncF {
        rectangle "陷阱指令 (int3 / brk)" as Trap
    }
    database "全局信号处理器" as SignalHandler
}

package "线程 A 本地存储 (TLS)" {
    database "模拟表 A\n(F -> M1)" as TLSA
}

package "线程 B 本地存储 (TLS)" {
    database "模拟表 B\n(空)" as TLSB
}


[线程 A] --> Trap : A.1. 调用函数 F
Trap -> SignalHandler : A.2. 触发 SIGTRAP
SignalHandler -> TLSA : A.3. 查询线程A的模拟表
TLSA --> SignalHandler : A.4. 发现模拟函数 M1
SignalHandler --> [模拟函数 M1] : A.5. 重定向执行流

[线程 B] --> Trap : B.1. 调用函数 F
Trap -> SignalHandler : B.2. 触发 SIGTRAP
SignalHandler -> TLSB : B.3. 查询线程B的模拟表
TLSB --> SignalHandler : B.4. 未发现模拟
SignalHandler --> [执行原始指令\n(通过蹦床)] : B.5. 重定向执行流

@enduml
```

### 4.2 线程隔离的核心

- TLS（thread_local!）为每个线程提供独立的 G_THREAD_REPLACE_TABLE：RefCell<HashMap<usize, Vec<usize>>>
- RAII 模式支持嵌套 mock：每线程对同一函数可形成“模拟栈”
- 全局状态最小化：仅维护 G_TRUNK_ADDR_TABLE: Mutex<HashMap<usize, usize>>

### 4.3 设计考虑（线程隔离）

- 线程本地存储（TLS）优先：避免锁竞争与伪共享
- RAII 与嵌套支持：Mocker Drop 时在本线程出栈并清理
- 信号处理器无锁与可重入：仅读 TLS，原子式寄存器调整
- 失败隔离：未模拟线程透明走“蹦床 + 恢复”路径

---

## 5. 关键挑战与解决方案

我们面临五个关键问题：权限（可写）、劫持（拦截执行流）、隔离（线程粒度生效）、重定位（PC 相对修复）、恢复（精确跳回）。以下给出整体解法。

### 5.1 权限与劫持：mprotect + 陷阱指令

- 使用 nix::mprotect 在运行时将目标页权限临时改为 RWX
- 在函数入口写入陷阱指令（x86_64 上的 int3，aarch64 上的 brk）
- 将被覆盖的第一条原始指令备份到“蹦床”

### 5.2 执行路径分发与线程隔离

- 全局信号处理器根据 TLS 判定：有模拟则重定向至新函数，无则执行蹦床中的原始指令

### 5.3 精确恢复（x86_64 单步；aarch64 一次跳回）

- x86_64：设置 EFLAGS.TF 进入单步模式，仅执行蹦床中一条重写指令，第二次 SIGTRAP 负责清除 TF、恢复寄存器并跳回 orig+len
- aarch64：不使用单步；蹦床包含“原始/重写指令 + 绝对跳回”，一次 SIGTRAP 即引导并返回

### 5.4 重定位（指令重写）

- x86_64：iced-x86 识别 RIP 相对寻址，挑选未使用的 caller-saved 寄存器作为“桥接寄存器”；在信号处理器中临时写入 next_ip 并执行重写后的指令
- aarch64：对 B/BL 等分支生成“LDR X17, #8; BR/BLR X17; <绝对地址>”；对 ADRP/ADR 在蹦床 PC 重编码或回退到“字面量装载 + 跳转/使用”；必要时对 literal LDR 采用保守序列避免 SIGILL

---

## 6. 平台差异与原因

### 6.1 x86_64 与 aarch64 的差异（概览）

- 入口陷阱：int3（1B） vs brk（4B）
- 未模拟路径：x86_64 两次 SIGTRAP 的单步恢复 vs aarch64 一次 SIGTRAP 的直接跳回
- 蹦床组织：x86_64 变长指令 + 3B 头；aarch64 4B 对齐 + 跳回序列 + 字面量地址
- 指令重写：寄存器桥接 vs 绝对地址序列/重编码
- 临时寄存器：动态选择 caller-saved vs 固定 X17
- I-Cache：通常无需显式刷新 vs 需要 dsb sy + ic ivau + isb
- 性能形态：精确单步（两次陷阱） vs 确定性跳回（一次陷阱）
- 兼容性：x86_64 倚重成熟单步；aarch64 强调对齐与缓存维护的保守策略

### 6.2 原因分析

- ISA 差异导致断点指令长度、PC 相对编码与重写成本不同
- x86 I/D cache 一致性由硬件保障；ARM 对自修改代码要求显式缓存维护
- 平台约定（如 X17 用作跳转寄存器）与 ABI 差异影响临时寄存器选择
- 调试能力差异决定了单步/跳回的可移植性与稳健性

---

## 7. 执行流程细化

### 7.1 x86_64 核心执行流程

```plantuml
@startuml
title x86_64 核心执行流程

start
:任何线程调用函数 F;
note right: 函数 F 的第一条指令已被替换为 `int3` (0xcc)

:执行 `int3` 指令;
:CPU 触发 `SIGTRAP` 信号;
note right: 内核激活全局信号处理器 `handle_trap_signal`

:信号处理器被调用;
if (当前线程在 TLS 中\n有函数 F 的模拟记录?) then (yes)
  partition "场景 A：需要模拟" {
    :修改 `RIP` 指向模拟函数 M;
    :信号处理器返回;
    :CPU 执行模拟函数 M;
  }
else (no)
  partition "场景 B：无需模拟（精髓）" {
    :修改 `EFLAGS` 寄存器, **设置陷阱标志位 (TF)**;
    note right: 进入单步调试模式
    :修改 `RIP` 指向“蹦床”中的原始指令;
    :信号处理器返回;
    :CPU **仅执行一条** 原始指令;
    :执行完毕后, CPU 因 TF 标志位\n**再次触发 `SIGTRAP`**;
    :信号处理器第二次被调用;
    :修改 `EFLAGS` 寄存器, **清除陷阱标志位 (TF)**;
    note right: 退出单步调试模式
    if (是否顺序落回?\nRIP == trunk_addr+3+new_len) then (yes)
      :计算原始指令的下一条指令地址 (orig_addr+old_len);
      :修改 `RIP` 指向该地址;
      :信号处理器返回;
      :CPU 从函数 F 的第二条指令\n继续无缝执行;
    else (no)
      :写回抑制：不修改 `RIP`，\n尊重已发生的控制流跳转;
      :信号处理器返回;
      :CPU 沿当前 `RIP` 继续执行;
    endif
  }
endif
stop

@enduml
```

#### 术语：写回抑制（x86_64）

- 概念：在第二次 SIGTRAP（单步执行完蹦床中的一条指令后）返回前，信号处理器检查是否“顺序落回”蹦床指令末端，即判断 RIP 是否等于 trunk_addr+3+new_len。若不相等，说明该指令改变了控制流（如 jmp/call/jcc/ret 等），此时不再将 RIP 写回 orig_addr+old_len，而是保留当前 RIP，让执行沿已发生的跳转继续，避免将已跳走的控制流强行拉回原函数。
- 代码对应：条件判断 if rip - (trunk_addr + 3) == new_len 成立才执行写回，否则触发“写回抑制”。

#### 7.1.1 当函数首条指令为跳转（jmp/call/jcc）时的行为（x86_64）

- 背景：当前 x86_64 的实现仅对“RIP 相对的内存操作数”进行重写与桥接（见源码中 Instruction::is_ip_rel_memory_operand 的分支），不会重写“以立即数编码的相对控制流”（如 JMP rel8/rel32、CALL rel32、Jcc rel8/rel32）。
- 流程回顾（未命中模拟路径时）：
  1) 第一次 SIGTRAP：设置 EFLAGS.TF 进入单步模式；读取蹦床头（old_len/new_len/replace_reg）；若 replace_reg 非 None，则把该寄存器写为 orig_next_ip = orig_addr + old_len；随后将 RIP 指向蹦床指令处（trunk_addr+3）。
  2) 单步执行 1 条蹦床指令；若该指令是“RIP 相对内存寻址”，则已被重写为 [reg+disp]，且 reg=orig_next_ip，行为与在原地执行等价。
  3) 第二次 SIGTRAP：清除 TF；若此时 RIP 仍等于 trunk_addr+3+new_len（即顺序落回蹦床下一条），则写回 RIP=orig_addr+old_len 继续执行原函数后续指令。若 RIP 已被跳转改写，则不再强制写回，直接沿当前 RIP 继续。
- 各类跳转的具体结果：
  - jmp/call/jcc 使用“寄存器间接”或“内存间接（且为 RIP 相对内存形态，如 jmp qword ptr [rip+disp32]）”：
    - 支持。对 RIP 相对内存形态，指令在蹦床中会被重写为 [reg+disp]，信号处理器将 reg 设置为 orig_next_ip，转移目标与原地执行一致；寄存器间接跳转本身与 RIP 无关，原地/蹦床等价。
  - jmp/call/jcc 使用“立即数相对位移”（rel8/rel32）：
    - 存在边界限制。蹦床中会按原 IP 重新编码出与原地相同的机器码，但在蹦床执行时，CPU 会基于“蹦床处的 RIP”计算目标地址，导致跳转目标相对偏移错误（原理：rel 位移以 next_ip 为基准，而蹦床与原地址不同）。该场景下未模拟路径可能跳转至错误位置，进而异常或崩溃。
    - 规避建议：
      - 若可控：避免被测函数的第一条指令为相对立即数跳转（例如在入口前插入一个无副作用的非控制流指令，或通过编译/链接选项改变布局）。
      - 若不可控：优先对调用点进行模拟（mock 调用者），或确保首条为“间接跳转/调用”而非“相对立即数”。
    - 后续改进方向：扩展重写器，针对相对控制流生成“装载绝对地址 + 寄存器跳转”的序列（与 aarch64 的思路类似），从而彻底消除对执行地址的依赖。

#### 实现细节：写回抑制（RIP 已跳转时不覆盖）

- 第二次 SIGTRAP（单步执行完蹦床指令后）中的核心逻辑是通过“是否顺序落回”来决定是否写回 RIP：
  - 判定条件：if rip - (trunk_addr + 3) == new_len
    - 其中 trunk_addr+3 是蹦床中重写后指令的起始地址（3 字节为蹦床头：old_len/new_len/replace_reg），new_len 为该重写指令长度。
  - 若条件为真：说明执行完该指令后，RIP 正好位于蹦床指令之后（即顺序落回），此时将 RIP 写回 orig_addr + old_len，让 CPU 从原函数的“下一条指令”继续执行。
  - 若条件为假：说明该指令改变了控制流（例如 jmp/call/jcc/ret 等），当前 RIP 已被改写到新的位置。为了尊重实际的控制流转移，信号处理器不再强行写回，直接沿“当前 RIP”继续执行。
- 其他配套处理：
  - 在第二次 SIGTRAP 中会先恢复被暂借的寄存器（replace_reg），确保寄存器语义不被破坏；RIP 的写回仅受上述“顺序落回”判定控制。
  - 该设计确保：顺序执行路径得到精确恢复；而发生跳转时不会被错误地拉回原函数，从而保持与原地执行一致的控制流。

### 7.2 aarch64 核心执行流程

```plantuml
@startuml
title aarch64 核心执行流程

start
:任何线程调用函数 F;
note right: 函数 F 的第一条指令已被替换为 `brk #0`

:执行 `brk #0` 指令;
:CPU 触发 `SIGTRAP` 信号;
note right: 内核激活全局信号处理器 `handle_trap_signal`

:信号处理器被调用;
if (当前线程在 TLS 中\n有函数 F 的模拟记录?) then (yes)
  partition "场景 A：需要模拟" {
    :修改 `PC` 指向模拟函数 M;
    :信号处理器返回;
    :CPU 执行模拟函数 M;
  }
else (no)
  partition "场景 B：无需模拟" {
    :修改 `PC` 指向“蹦床”地址;
    note right: “蹦床”包含：\n1. 原始指令\n2. 跳转回 F+4 的指令
    :信号处理器返回;
    :CPU 从“蹦床”开始执行;
    :执行完原始指令后，\n自动跳转回原函数 F 的\n下一条指令继续执行;
  }
endif
stop

@enduml
```

#### 7.2.1 为什么 aarch64 没有单步/写回抑制机制？是否不需要？

- 设计选择：aarch64 路径采用“一次 SIGTRAP + 自包含蹦床”的确定性流程，不依赖单步。信号处理器只负责把 PC 指向蹦床：
  - 若首条是分支（B/BL/B.cond 等）：在 save_old_instruction 的分支处理路径中，会将相对分支重写为“LDR X17, #8; BR/BLR X17; <绝对目标地址>”，直接跳向真实目标，不再返回原函数入口。这等价于 x86_64 中“RIP 已被改写则不写回”的效果，但由蹦床自身保证，无需在信号返回时再做判断。
  - 若首条为非分支：蹦床末尾固定附加“LDR Xt, #8; BR Xt; <orig+len>”的跳回序列，执行完原始/重写指令后自动回到 orig+len 继续，无需第二次 SIGTRAP。
- 为什么不实现单步：
  - 可用性与复杂度：x86_64 通过 EFLAGS.TF 可直接进入单步；aarch64 的单步需要操作调试状态（如 PSTATE.SS/调试寄存器）并通常经由 ptrace 等机制，在信号处理器内启停不如 x86 简便、可移植。
  - ISA 特性：aarch64 指令定长 4 字节，易于在蹦床中构造“绝对跳转/跳回”序列；相对分支与 PC 相对访问可以在蹦床处重编码或改为“装载绝对地址 + 间接跳转/访问”，因此无需依赖单步去“原位执行”。
  - 稳健性与兼容：一次 SIGTRAP 避免两次陷阱带来的时序/嵌套信号问题；在 QEMU 等仿真环境更稳定。实现中也配套执行 I-Cache 刷新，保证自修改代码一致性。
  - 性能：单次陷阱比两次陷阱更低开销。
- 是否不需要：是。由于蹦床已分别对“分支”和“非分支”路径提供了精确的前进/回跳语义，aarch64 不需要在信号返回时做“写回抑制”判断；控制流转移由蹦床指令序列直接体现。

---

## 8. 实现细节

### 8.1 关键数据结构

- 全局蹦床地址表：G_TRUNK_ADDR_TABLE: Mutex<HashMap<usize, usize>>（原函数入口 -> 蹦床地址）
- 线程本地模拟表：G_THREAD_REPLACE_TABLE: thread_local RefCell<HashMap<usize, Vec<usize>>>（原函数 -> 模拟函数栈）
- 作用域恢复：Mocker 的 Drop 在本线程内出栈并清理

### 8.2 代码区与内存管理

- 通过 mmap 分配可读/写/执行的“代码区”作为蹦床区域
- 默认容量：8 页（PAGE_SIZE=4096），可通过环境变量 MOCKRS_CODE_AREA_SIZE_IN_PAGE 调整
- Droper 的 Drop 在进程退出时 munmap 回收

### 8.3 内存权限

- 写入函数入口或蹦床时，使用 mprotect 临时修改目标页权限为 RWX
- aarch64 场景下，每次写入后执行 dsb sy + ic ivau + isb 刷新指令缓存

### 8.4 蹦床格式

- x86_64：3 字节头（old_len/new_len/replace_reg）+ 重写后的单条指令；指令变长，无固定对齐
- aarch64：3 字节头 + 4 字节对齐填充 + 重写指令序列 + 跳回指令 + 8 字节字面量地址

### 8.5 指令重写策略

- x86_64：iced-x86 解析 RIP 相对寻址，动态选择 caller-saved 寄存器作为桥接，信号路径内负责寄存器保存/恢复
- aarch64：对分支/PC 相对指令进行重编码或使用“LDR X17 + BR/BLR + 字面量地址”的保守序列；在仿真环境下优先稳健方案避免 SIGILL

#### 8.5.1 x86_64 临时寄存器（桥接寄存器）设计

- 设计目标：当首条指令含 RIP 相对的内存操作数（如 mov rax, [rip+disp]）时，需在“蹦床地址”正确取数。做法是把该内存基址从 RIP 改写为一个“临时寄存器 r_tmp”，并在信号路径中临时把 r_tmp 设为 next_ip（orig_addr + old_len），使 [r_tmp + disp’] 与原地等价。
- 候选集合（遵循 System V x86_64 ABI 的 caller-saved）：{ RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11 }。
- 选择策略：使用 iced-x86 的 InstructionInfoFactory::used_registers() 剔除所有显式/隐式已用寄存器，从候选集合中选取首个未使用者作为 r_tmp，避免破坏被测指令语义。
- 重写与编码：
  - 将指令的内存基址从 RIP 改为 r_tmp；
  - 将位移改写为 (EA - next_ip)，EA 为原指令计算出的有效地址，next_ip 为原指令的下一条指令地址；
  - 将重写后的机器码写入蹦床，并在蹦床头记录 old_len/new_len/replace_reg（r_tmp）。
- 信号路径与恢复：
  - 第一次 SIGTRAP（未命中模拟）：读取蹦床头；保存 r_tmp 原值；写 r_tmp = orig_addr + old_len；设置 TF 单步并跳入蹦床；
  - 第二次 SIGTRAP：恢复 r_tmp 原值；若顺序落回（RIP == trunk_addr+3+new_len）则把 RIP 写回 orig_addr+old_len，否则触发“写回抑制”，保留当前 RIP。
- 实现备注：
  - 当前实现的上下文寄存器索引映射涵盖：RAX、RBX、RCX、RDX、RDI、RSI；后续可扩展到 R8–R11 以与候选集合完全一致。
  - r_tmp 属于 caller-saved，且在第二次 SIGTRAP 恢复，满足 ABI 约定与语义正确性。

#### 示意图：x86_64 临时寄存器桥接流程

```plantuml
@startuml
title x86_64 临时寄存器桥接流程

start
:反汇编并检测 RIP 相对内存操作数;
:收集 used_registers();
:从 {RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11}\n中挑选未使用的 r_tmp;
:把 [rip+disp] 改写为 [r_tmp + (EA - next_ip)];
:写入蹦床并记录 replace_reg=r_tmp, new_len;

partition "SIGTRAP #1（未命中模拟）" {
  :读取蹦床头 old_len/new_len/replace_reg;
  :orig_next_ip = orig_addr + old_len;
  :保存 r_tmp 原值; 
  :写 r_tmp = orig_next_ip;
  :设置 TF; RIP = trunk_addr+3; 返回;
}

:CPU 单步执行重写后的指令;

partition "SIGTRAP #2" {
  :恢复 r_tmp 原值;
  if (RIP == trunk_addr+3+new_len?) then (是)
    :RIP = orig_addr+old_len; 返回;
  else (否)
    :写回抑制：保持当前 RIP; 返回;
  endif
}
stop
@enduml
```

### 8.6 核心技术栈

- nix：封装 POSIX 系统调用
- lazy_static：安全初始化全局静态数据
- iced-x86（x86_64）与 capstone（aarch64）：反汇编与编码机器指令

---

## 9. 使用约束与最佳实践

- 函数签名需匹配：模拟函数参数与返回值应与原函数一致。
- 内联与可挂钩性：被完全内联的函数没有独立入口，无法挂钩；测试中可临时标注 #[inline(never)]。
- 泛型函数：经单态化生成的具体实例通常可模拟，但需确保该具体实例存在可寻址符号。
- FFI 函数：可模拟，需保证符号可解析且存在入口（动态链接函数通常亦可）；请在测试环境中评估平台差异。
- 异步与线程：mock! 仅在创建它的线程生效。异步执行若跨线程调度，模拟不会随任务迁移；需要时可在单线程运行时或显式线程边界内使用。
- 嵌套与栈语义：同一线程对同一函数可多次 mock，形成“后进先出”的覆盖栈；Drop 时对应条目出栈并在栈空时清理。
- 安全与合规：依赖 RWX 可执行内存与自修改代码，仅建议在测试/开发环境使用；aarch64 下请遵循 I-Cache 刷新序列。
- 失败处理：未模拟线程/路径将透明走“蹦床 + 恢复”流程，确保最小侵入与可预测性。

---

## 10. 工程化与测试

- CI 跨架构验证：仓库提供 GitHub Actions 工作流，除常规 x86_64 编译/测试外，还通过 qemu-user-static 在 Ubuntu 上透明执行 aarch64 目标二进制，并使用 aarch64-linux-gnu 工具链进行交叉编译与链接。关键步骤：
  - 安装 qemu-user-static 和 binfmt-support，并启用 qemu-aarch64
  - 安装 aarch64 交叉工具链与运行时依赖（gcc-aarch64-linux-gnu、libc6-dev-arm64-cross、libc6:arm64 等）
  - 安装 Rust 工具链并添加 aarch64-unknown-linux-gnu 目标
  - 设置环境变量：
    - CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    - QEMU_LD_PREFIX=/usr/aarch64-linux-gnu
  - 分别执行 cargo build/test --target aarch64-unknown-linux-gnu

- 本地运行 aarch64 测试：在开发机上同样可通过上面的工具链与环境变量，借助 QEMU 用户态仿真透明运行 aarch64 目标的测试。

---

## 11. 效果评估

- 通用性：实现“万物皆可模拟”，覆盖自由函数、具体方法与 FFI 场景
- 低侵入性：无需为测试重构生产代码（如强行引入 Trait）
- 接口简洁：mock! 宏屏蔽底层复杂度
- 并发安全：线程隔离设计可支撑并行测试而不发生状态污染

---

## 12. 局限性与未来展望

### 12.1 当前局限性

- 性能开销：每次调用都会触发 SIGTRAP，开销高于常规调用；不适合性能极致场景
- 无法模拟被完全内联的函数：编译器内联后缺失独立入口，无法挂钩
- 极短函数/特殊布局：若入口替换不安全，则可能失败（实践中罕见）

### 12.2 未来展望

- 性能优化：探索更高效的蹦床技术（如按需写回，减少后续陷阱）
- 更广平台：扩展到更多 CPU 架构与系统（含 32 位与 Windows）
- 更强 API：如调用次数统计、参数捕获等高级能力

---

## 13. 安全与合规说明

- 代码区与目标页以 RWX 方式写入，适用于测试与开发环境；生产环境需充分评估风险与合规性
- aarch64 下自修改代码需严格执行 I-Cache 刷新序列

---

## 14. 结论

mockrs 以“全局提问、线程本地回答”为核心思想，通过最小侵入的入口陷阱与稳健的架构适配，解决了传统基于 Trait 的模拟方案无法触及的自由函数/FFI 等场景，并在多线程条件下提供可证的隔离与恢复能力。该方案为 Rust 的复杂测试需求提供了强大而务实的工具基础。

附录：常见问题 FAQ

- Q: 可以模拟哪些函数？
  A: 只要有可寻址的函数入口即可，包括自由函数、具体方法与多数 FFI 符号（动态链接函数一般也可）。闭包与内联后的代码无法模拟。
- Q: 与原函数签名需要一致吗？
  A: 是。模拟函数的参数、返回值需与原函数一致，否则行为未定义。
- Q: 遇到被内联的函数怎么办？
  A: 在测试配置中为目标函数临时加 #[inline(never)]，确保生成独立入口。
- Q: 多线程/异步下如何使用？
  A: mock! 仅在创建它的线程生效。异步任务若跨线程调度，模拟不会跟随任务迁移；可在单线程运行时或固定线程池中使用。
- Q: 是否支持嵌套多次 mock 同一函数？
  A: 支持，同线程内形成覆盖栈；Drop 时按栈语义恢复。
- Q: 能否用于生产环境？
  A: 不建议。该方案依赖 RWX 内存与自修改代码，主要为测试/调试场景设计。
- Q: 模拟 FFI 有何注意事项？
  A: 确保符号已链接且在运行时可解析；在 aarch64 下注意 I-Cache 刷新，避免在早期启动阶段修改尚未映射完成的页。
