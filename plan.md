This is a copy of a shared ChatGPT chat. It won't be added to memory.

Report conversation
CTF Web 工具平台：基于 Writeup 的第二轮查漏补缺

这轮检索发现：你之前的 18 个模块已经覆盖了大部分传统 CTF 工具，但还有一些高复用价值的解题操作没有被单独识别出来，尤其是 USB-HID 流量重建、Git 历史取证、恶意脚本解包、协议数据重组，以及近年新增的 AI、区块链、移动端、云环境和工业控制题型。

我主要对照了以下资料：

Hack The Box Cyber Apocalypse 2025 官方题解
。

Cyber Apocalypse 2026 官方题解
，覆盖 Forensics、Mobile、Hardware、ICS、Cloud、AI/ML、GamePwn、Quantum 等。

IrisCTF 2025 USB 取证 Writeup
，以及 UofTCTF、picoCTF、ACECTF 等比赛题解。

多位选手的独立博客，以及专门实现某类攻击、解析或取证步骤的开源工具。

2026 年官方题解尤其值得关注：除了传统的 Web、Crypto、Pwn、Reverse，已经出现 Git 悬空对象恢复、TLS 流量与进程转储联合分析、Modbus/PLC、Godot 游戏资源、LLM/AI、硬件固件等具体任务。这些并非都适合完整搬进浏览器，但其中许多中间处理步骤很适合做成工具。
GitHub
+2

以下的“高频、中频、专项”属于所检索题解中的定性重复度，不是所有 CTF 比赛的统计频率。 我会把功能区分为三种状态：此前未提及、此前提过但不完整、已有能力需要串成自动流程。

一、优先关注的遗漏

功能簇

	

之前的覆盖情况

	

观察到的复用价值

	

建议




USB 键盘、鼠标流量还原

	

缺失

	

高频

	

P0




Git 悬空对象、历史秘密恢复

	

缺失

	

中频

	

P0




恶意脚本分层解混淆

	

部分覆盖

	

高频

	

P0




PCAP 数据重组、隐蔽信道提取

	

不够完整

	

高频

	

P0




自动提取与解码流水线

	

已提出，需细化

	

高频

	

P0




压缩包加密格式分析与恢复

	

不够完整

	

中频

	

P1




固件、嵌入式设备、串口

	

缺失

	

专项

	

P1




Android、iOS、游戏资源

	

仅部分覆盖

	

中频

	

P1




Blockchain / Smart Contract

	

基本缺失

	

专项

	

P1




AI / ML / LLM 安全题

	

缺失

	

新兴专项

	

P1




Cloud / Container / IAM 取证

	

不够完整

	

中频

	

P1




工业控制 / PLC / Modbus

	

基本缺失

	

专项

	

P2

这里我更看重的是一道题里的某个操作能否被不同题目反复复用，而不是简单统计某类题出现了多少次。比如一道很复杂的逆向题无法自动求解，但它里面的“提取常量 → 重排字节 → 识别 PRNG → 逆向计算”可以拆成四个通用工具。

二、从 Writeup 中抽取的具体工具需求
1. USB-HID Forensics：键盘与鼠标流量重建
强烈建议 P0

这是之前清单中比较明显的遗漏。

实际例子：

IrisCTF 2025 deldeldel：通过 USB PCAP 识别键盘端点、提取 HID Report，再恢复按键。

Fetch the Flag 2025 ClickityClack：使用 tshark 提取数据，再用 USB Keyboard Parser 恢复输入。

MetaCTF 2025 Hunt and Peck：从鼠标流量还原轨迹和点击位置，再映射到 Windows 屏幕键盘。
ctftime.org
+2

值得实现的标准化操作

从 PCAP / PCAPNG 中识别 USB Endpoint、设备、HID Report Descriptor。

自动区分常见 Boot Keyboard、Mouse，以及非标准 Report 布局。

提取 usb.capdata、usbhid.data 等字段，支持原始数据偏移提取。

键盘扫描码转字符、键盘布局切换（US / UK / 中文输入相关键位等）。

正确处理 Shift、CapsLock、组合键、按住、释放、Backspace。

USB 鼠标相对位移累加、轨迹绘制、点击位置标记。

支持 DPI / 缩放 / 画布偏移调整、背景键盘图叠加。

导出重建文本、鼠标坐标 CSV、PNG / SVG 轨迹。

连接通用解码工作流，继续处理恢复出来的密文。

建议独立做成 HID Reconstruction Lab，而不是藏在 PCAP 查看器的某个菜单里。

2. Git Forensics：版本控制取证
P0

2026 年 Cyber Apocalypse 的 Force Push 就是从 Git 不可达对象恢复被删除的生产密钥。Git 的特殊之处是：文件从当前分支消失，并不意味着对应 Blob 已经从仓库对象库中被清理。
GitHub
+1

应增加：

Git 仓库 ZIP / .git 导入。

Commit Graph、Refs、Tags、Branches、Reflog 浏览。

Dangling / Unreachable Commit、Tree、Blob 枚举。

Deleted File、Rebase、Reset、Amend 前内容恢复。

Stash、工作树、索引文件差异分析。

Packfile、Loose Object、Delta Object 解析。

Git Object 全量字符串 / Hex / Regex 搜索。

Git 历史 Secret Scan、Flag Pattern 扫描。

历史版本 Diff、文件重建、内容导出。

.git 目录文件集合重建仓库。

这一模块适合基于现有 Git 库实现只读离线分析。网络上对 .git 暴露的探测则应该和仓库文件的本地分析分开。

3. Malware Script Unpacker：恶意脚本与混淆代码拆层
P0

2025 年 HTB Thorin's Amulet 的处理流程包括 PowerShell 中提取 Base64、解码后发现下一阶段 URL；ToolPie 使用了压缩的 Python marshal 数据；Cave Expedition 涉及 Windows 事件日志、编码的 PowerShell 和 XOR 数据恢复。
GitHub
+1

之前的清单虽然有 JavaScript 去混淆、Python .pyc，但缺少面向 分层脚本 的统一自动解包器。

应增加：

PowerShell -EncodedCommand UTF-16LE 解码。

Base64 / Hex / CharCode 数组自动提取。

PowerShell 字符串拼接、格式运算、反转、XOR 模式识别。

PowerShell、VBScript、Batch 常见混淆结构还原。

Python marshal、zlib、bz2、lzma 嵌套分析。

Python Code Object 的常量、变量、字节码、版本检查。

JS eval、atob、String.fromCharCode、字符串数组访问还原。

PHP base64_decode、gzinflate、str_rot13 等嵌套调用拆解。

JavaScript AST、PowerShell AST 可视化。

多层解码树和中间产物导出。

API、URL、IP、加密密钥、文件路径 IOC 提取。

关键设计要求：静态拆解优先，不能把导入的可疑脚本直接 eval 或 exec。 对不可静态求值的步骤，单独提供受限制的动态分析环境。

4. Network Data Reconstruction：协议载荷重组
P0

PCAP 解析器在之前的计划中已有，但 Writeup 中经常出现的并不是复杂协议分析，而是：

提取指定协议字段 → 按某种顺序拼接 → 清除冗余字节 → 解码 → 得到文件或 Flag。

例如 ACECTF 2025 Hidden in the Traffic 从 ICMP Echo 数据中提取消息，再删除重复填充文本。FLARE-On 2025 的网络逆向题也需要导出 HTTP 对象、检查 JSON 消息以及恢复自定义协议。
Shreethaar's CTF WriteUps
+1

建议拆出以下操作：

DNS Query Label Extraction、按序拼接。

DNS TXT / A / AAAA 记录中的编码数据恢复。

ICMP Echo Payload、IP ID、TTL、TCP Sequence 字段提取。

TCP Stream Reassembly、乱序数据和重传去重。

HTTP Chunked / Multipart / Gzip Body 重建。

HTTP 请求参数、Cookie、Header 的批量字段提取。

自定义二进制协议 Length Prefix / Delimiter 拆包。

按时间、序列号、包编号排序。

按固定宽度拆分、移除公共前后缀、去重。

从协议数据中自动识别图片、ZIP、PDF、音频。

时间间隔隐写：将包间隔映射成比特或符号。

包大小、方向、顺序的隐蔽信道分析。

TLS Key Log 导入、解密后的流量再次解析。

蓝牙 HCI、Wi-Fi 802.11 帧基础解析。

这里最值得复用的是底层 Extract Field → Group → Sort → Reassemble → Decode 操作链。它不仅适用于 DNS 和 ICMP，也能用于 USB、串口、工业协议和自定义 C2 通信。

5. Windows Artifact Timeline：日志关联与事件重建
P1

2025 年多个 HTB Forensics 题解反复用到 PowerShell、Windows Event Log、浏览器记录和恶意软件行为分析。2026 年的 Remnant 更进一步，把 PCAP、进程 Minidump、TLS 会话密钥、RDP、C2 和外部存储操作关联起来。
GitHub
+1

除了之前已经规划的 EVTX、Registry、Prefetch，还值得补：

Sysmon Event ID 及进程树关联。

Windows Defender、PowerShell Operational 日志。

Scheduled Task、WMI Persistence、Services 解析。

Amcache / Shimcache / BAM / UserAssist。

SRUM、Jump List、LNK 与 ShellBags。

Chrome / Chromium / Firefox 会话、下载记录、扩展记录。

SQLite WAL 和浏览器已删除记录恢复。

KAPE、Velociraptor 类采集结果导入。

Plaso、Hayabusa 风格时间线文件导入。

自动统一 UTC / 本地时间，事件去重、关联。

进程、IP、域名、文件、Hash 之间的关系图。

RDP 画面重建及事件回放（高级功能）。

这一模块真正的差异化应该是自动关联，而不只是分别读取 20 种日志文件。

6. QR Recovery Lab：二维码结构化修复
P0

之前只规划了二维码识别、反色和简单破损修复，但 2025 年 New Year CTF 的 Broken QR 表明，这远远不够。

这道题使用 QRazyBox，通过修复定位图案、对齐图案，再利用 Reed–Solomon 纠错恢复数据。
ctftime.org

建议增加一个像素网格编辑器，支持：

自动识别 QR Version、Size、Module Grid。

手动逐模块编辑黑白值，锁定已知区域。

定位图案、对齐图案、Timing Pattern 自动修复。

Format Information、Version Information 分析。

QR Mask Pattern（0–7）枚举和解除掩码。

Reed–Solomon Codeword、纠错 Syndromes 检查。

Data Codewords、Error Correction Codewords 可视化。

缺失或未知模块的约束搜索（限定规模）。

旋转、镜像、颜色反转、透视矫正。

多张局部二维码拼接。

解析普通 QR、Micro QR、Data Matrix（分别实现）。

显示恢复后的原始比特流，而不只是文本。

值得借鉴的工具：
QRazyBox
。

7. Frame Forensics：多帧图像隐写
P1

2025 年 openECSC Calamansi 题解发现，动画帧的 Alpha 全为 0，但透明像素的 RGB 数据仍然构成了文字。解题关键是遍历帧并忽略 Alpha 重新渲染。
CTF Writeups

应增加：

GIF / APNG / WebP / TIFF 多帧导出。

忽略透明度，显示透明像素原始 RGB。

帧叠加、帧差、逐帧 XOR、求均值 / 最大值。

帧间奇偶分组、按时间间隔筛选。

动画 Disposal Method、Frame Offset、Delay 检查。

相邻帧变化区域提取。

帧顺序重排与索引映射。

多帧数据按位拼接、按颜色或坐标抽取。

对每一帧批量运行 LSB、OCR、QR、Magic Scan。

这应做成专门的 Frame Analyzer，让用户能够在同一个页面里查看原图、合成图、透明 RGB 和帧差。

8. Archive Recovery：不只是压缩与解压
P1

BuckeyeCTF 2025 的 zip2john2zip 很有代表性：不仅要分析 ZIP Hash，还涉及从 Hash 中记录的结构信息恢复压缩包内容。
ctftime.org

建议补充：

ZIP Local / Central Directory 不一致检查。

ZIP / RAR / 7z 的加密算法识别。

ZIP Hash、RAR Hash、7z Hash、PDF Hash、KeePass Hash 提取。

zip2john、rar2john、7z2hashcat 格式导出。

对给定字典和 Mask 进行有限预算的口令测试。

ZipCrypto 已知明文攻击（bkcrack）。

根据 ZIP 文件结构、已知内容恢复损坏归档。

分离 ZIP 目录、压缩数据和加密头。

ZIP Polyglot、重叠条目、重复文件名检测。

加密文件、混合文件、嵌套文件关系显示。

导入损坏归档时尝试 File Carving。

bkcrack 的已知明文恢复是很标准化的算法，适合提供专门界面；但它针对传统 ZipCrypto，并不意味着可以直接恢复所有 AES 加密 ZIP。
GitHub

9. Password / Key Material Lab
P1

之前的 Hash 模块主要关注哈希计算与识别，但 Writeup 里常用的是从特定格式中抽取可测试的凭据材料，再匹配相应恢复方法。

新增操作：

SSH、PDF、KeePass、Office、ZIP / RAR / 7z 加密信息检查。

Hash 格式识别、John / Hashcat Mode 推荐。

ssh2john、keepass2john、pdf2john 等兼容导出。

NTLM、NetNTLM、Kerberos Hash、Unix Shadow 格式解析。

字典规则、Mask、字符集、排列组合生成。

有限范围密码候选测试、进度和计算预算控制。

已知密钥、口令、IV、Nonce 批量整理及试解。

成功解锁后将解密文件直接送入文件分析引擎。

这类操作在 CTF 密码恢复中有成熟工具链。
CTF Support

10. Crypto Oracle & Nonce Analyzer
建议 P0/P1

之前有 RSA 攻击、AES 模式和密钥处理，但缺少两个十分实用的交互工作台。

A. Nonce Reuse Analyzer

导入多条明文、密文、IV / Nonce、Tag。

自动归组同 Key / Nonce 的数据（在密钥标识已知时）。

CTR / GCM 密钥流复用检测。

XOR 两份密文，执行 Crib Dragging。

AES-GCM GHASH 参数分析。

ECDSA 重复 
𝑟
r 值检测。

ECDSA 相同 Nonce 恢复、部分 Nonce 泄露的格攻击。

PRNG 输出序列检查，LCG、MT19937 状态恢复。

批量签名 / 密文 CSV、JSON 导入。

2025 年 Black Hat MEA CTF 的题解实际使用了 AES-GCM Nonce 复用和 GHASH 计算。
GitHub

B. Oracle Workbench

自定义合法 / 非法响应条件。

选择输入数据中的一个字段作为探测变量。

将响应按 Status、Length、Content、Timing 分类。

保存每次 Probe 的输入、输出及耗时。

为 Padding Oracle、RSA LSB Oracle 等设计可配置求解器。

统计噪声、重试次数、错误率。

支持本地模拟 Oracle，先验证算法再连接授权的 CTF 服务。

比起提供固定的“RSA 在线破解”，这一工作台能支持更多不同题目中的 Oracle 模型。

11. Disk Forensics：补足真正的磁盘操作链
P1

picoCTF 的磁盘类题解通常不是直接对 .img 运行 strings，而是先识别分区，查看文件系统，再通过 inode、文件记录或时间线定位目标数据。2026 年的 Timeline-0 题解还使用了 fls 和 mactime 重建文件系统活动时间线。
primer.picoctf.org
+1

在之前的磁盘镜像分析器上补充：

mmls 风格分区表浏览。

fsstat 风格文件系统元数据检查。

fls 风格目录树与删除文件枚举。

icat、blkcat 风格 inode / Block 提取。

MACB 时间线生成、Timestomping 检查。

Slack Space、Unallocated Space 搜索。

NTFS Alternate Data Streams（ADS）提取。

NTFS Zone.Identifier 来源信息解析。

Ext4 Journal / NTFS LogFile 等恢复辅助。

按时间、路径、大小、Hash 筛选文件。

这些功能还适合和 Git 取证、Windows Artifact Timeline 共用一个时间线视图。

12. Reverse Unpacker：程序打包格式专用解析
P1

2025 年 FLARE-On 和其他逆向题解中，PyInstaller → 提取 .pyc → 识别 Python 版本 → 反编译，是可以高度形式化的过程。2025 年 Chain of Demands 就直接使用 pyinstxtractor 和 PyLingual 恢复了 Python 源码。
milanspinka.com

此前的 Reverse 模块列过反编译器，但没有详细列出这些格式适配器：

PyInstaller、PyArmor、Nuitka、PyOxidizer。

Python .pyc 魔数 → Python 版本识别。

Java JAR、Kotlin JVM、DEX、Dalvik OAT。

.NET Assembly、Mono、NativeAOT 元数据。

Electron ASAR、NW.js、Node SEA、Nexe、pkg。

UPX、常见 PE Packer 签名。

WASM / WAT、LLVM Bitcode、Lua Bytecode。

固件专用指令集、MicroPython .mpy。

自定义 VM Bytecode 指令字段与 Opcode 映射。

自动提取字符串表、常量表、代码段、嵌入资源。

建议输出格式始终一致：文件结构树 + 提取文件 + 字节码/源码视图 + 元数据 + 可下载产物。

13. Binary Constraint Lab：逆向与 Pwn 的约束工具
P1

2026 年 HTB 的 The Hinge Whisper 涉及 64 字节 Shellcode Buffer 和控制流劫持；其他题目使用不同的字节限制、偏移和编码方式。独立的约束验证器能反复使用，而不需要每题手写脚本。
GitHub

建议补充：

Shellcode 长度、禁止字节、允许字符集检查。

Shellcode ASCII / Hex / Escape 输入转换。

Bad Byte 自动定位。

简单 Shellcode Encoder / Decoder。

Assembly ↔ Machine Code 与指令长度比较。

指令组合搜索、指定长度填充。

ROP Gadget 的寄存器副作用、栈变化、约束过滤。

Seccomp BPF 反汇编与允许 Syscall 视图。

ELF / libc / loader 版本及符号偏移比较。

ASLR、PIE、Canary、RELRO 状态检查。

Format String Payload 字节长度与位置参数计算。

GDB Trace、寄存器与内存状态可视化。

对小规模校验逻辑生成 Z3 约束。

高级的自动利用和符号执行可以作为后端能力，但独立的小型约束检查器已经很有用。

14. Mobile & Game Assets Lab
P1

这两部分此前被合并进普通 Reverse，但实践上值得拥有独立的文件入口。

TFCCTF 2025 的 Android 题解使用 JADX 分析 APK，再处理 JNI 和原生库；强网拟态 2025 的 Mobile 题则涉及 Unity IL2CPP、global-metadata.dat、加密的原生库和动态分析。
Android Reverse (TFCCTF 2025)
+1

Mobile

APK / AAB / IPA 文件结构浏览。

AndroidManifest、权限、Activity、Service、Receiver 解析。

APK / DEX / Smali 浏览、资源解包。

JNI Native Method 映射。

Android 证书、签名、Package 信息分析。

SharedPreferences、Room / SQLite、Assets 检查。

Android Backup、ADB Backup 解析。

Frida Hook 日志导入、调用链整理。

Flutter Snapshot / Dart AOT、HarmonyOS HAP 适配。

GamePwn

Unity AssetBundle、UnityFS、SerializedFile 浏览。

IL2CPP Metadata、Mono Assembly 解析。

Godot PCK、PCK 加密状态、场景资源提取。

Unreal Pak、IoStore 格式检查。

Ren'Py RPA / RPYC、RPG Maker 数据文件。

游戏存档结构分析、值对比、差分。

Lua Bytecode、游戏资源脚本提取。

存档修改前后差异与校验值分析。

15. AI / ML CTF Lab
P1

2025 年 HTB 的 Enchanted Weights 将信息藏进 PyTorch 权重矩阵；Crystal Corruption 使用了 PyTorch 文件中的恶意 Pickle 内容，同时在 Tensor 中隐藏数据。
ML Writeup
+1

Model Forensics

PyTorch .pth / .pt 文件静态结构检查。

Safetensors、ONNX、TensorFlow SavedModel、Keras 格式解析。

Pickle Opcode 反汇编、危险反序列化行为检测。

不执行模型代码地读取 Tensor Metadata。

Tensor Shape / Dtype / Stride / Weight 分布分析。

Tensor 1D / 2D / 3D 可视化。

Tensor 数值映射 ASCII / Unicode / 像素 / Bit Stream。

Tensor LSB / IEEE 754 位平面扫描。

权重差异、异常值和稀疏分布分析。

模型文件嵌入额外数据检测。

LLM / Prompt Security

Prompt / Response 多轮对话测试台。

变量模板、不同提示组合批量执行。

输出 Diff、相似度、关键词、JSON 格式比较。

模型安全测试集的本地评测与回放。

Tokenizer、Token ID、特殊 Token 浏览。

Prompt Injection 成功条件定义与结果标记。

RAG 文档、Tool Call、引用来源追踪。

模型响应随机性、温度及重复测试统计。

LLM 测试台更适合做成对授权模型进行可复现评测的框架，而不是固定的“万能提示词破解器”。

16. Blockchain / EVM Lab
P1

PwnMe 2025 和 HTB 2025 的 Blockchain 题解都出现了读取合约 ABI、调用函数、解析链上状态、使用 Foundry 操作测试链的步骤。
ctftime.org
+2

可 Web 化的具体功能：

Solidity ABI Encoder / Decoder。

Function Selector（4-byte）与 Event Topic 计算。

Transaction Input / Calldata 解码。

Transaction Receipt、Logs、Event 解码。

EVM Storage Slot / Mapping Slot 计算。

Packed Storage Layout 解析。

合约 Bytecode Metadata、Compiler Version 识别。

Solidity Source / Bytecode 查看。

ERC20 / ERC721 / ERC1155 数据解析。

EIP-712 Typed Data、Keccak256、RLP、EIP-1559。

CREATE / CREATE2 地址计算。

交易调用序列、余额与状态变化可视化。

智能合约在本地测试链执行、快照、回滚。

Foundry Cast / Forge 常见操作的 Web 前端。

这部分完全没必要重写 EVM。只需要把 ABI、RPC、Storage、Tracing 等可形式化操作组织成工作台，再提供本地模拟链。

17. Hardware & Signal Lab
P1

2025 年 DaVinciCTF 的 Golden Scarab 使用逻辑分析仪分析 UART 和 Manchester 编码。2026 年 HTB 的 Debug 则给出 Saleae .sal 采样数据，需要恢复 UART 串口内容。
Hippie
+1

建议补：

Saleae .sal、PulseView .sr、VCD、CSV 导入。

波形显示、逻辑边沿检测、采样率转换。

UART 波特率、Data Bits、Parity、Stop Bits 自动枚举。

SPI CPOL / CPHA、MSB / LSB 顺序。

I²C、1-Wire、CAN Bus、LIN 基础解析。

Manchester、Differential Manchester、NRZ、NRZI 编解码。

Pulse Width、Pulse Distance、PWM 数据恢复。

Flipper .sub、.ir、Sub-GHz 捕获分析。

SDR IQ 数据（I/Q）波形、频谱、星座图。

AM / FM / FSK / ASK / PSK 解调。

AX.25 / APRS、SSTV、DTMF、Morse。

GPIO / JTAG / SWD 日志、Memory Dump 辅助查看。

EEPROM、Flash Dump 的文件结构及字符串扫描。

ESP32 / ESP8266、ARM MCU 固件基础解析。

其中逻辑分析仪的自动波特率、协议参数枚举可以做成很通用的工具。

18. Industrial Control / ICS Lab
P2

2026 年 HTB 已出现 Modbus/TCP、PLC Ladder Logic、工控寄存器和 HMI 的完整题型；独立的 Factory 题解还包括 Modbus RTU 与 PLC Coil 解析。
GitHub
+1

适合 Web 化的部分：

Modbus RTU / TCP ADU、PDU 字段解析。

Function Code、Unit ID、寄存器、线圈解析。

CRC16-Modbus 计算、请求与响应配对。

Coil、Discrete Input、Holding/Input Register 转换。

S7comm、EtherNet/IP、DNP3 协议查看。

PLC 寄存器映射、设备地址表格。

Ladder Logic 只读查看与仿真。

HMI 变量与 PLC 地址映射。

工控 PCAP 回放和事件时间线。

本地 PLC 状态机模拟器。

这里尤其需要默认离线分析。实际工控设备的写寄存器、修改 Coil 等操作不能作为自动探测功能直接发往任意目标。

19. Cloud & Container Forensics
P1

UofTCTF 2025 Out of the Container 的核心是查看 Docker 的早期镜像层，找回在后续层中被删除的文件。2026 年 HTB False Order 则使用 CloudTrail、IAM、STS 和 S3 事件重建操作链。
Status 418
+1

Container

Docker save Tarball / OCI Layout 解析。

manifest.json、index.json、Config、History 查看。

Layer Diff、Whiteout File 检查。

被删除文件、旧版本文件恢复。

ENV、ARG、构建命令及 Secret 扫描。

Docker Layer File Explorer。

OCI Registry Manifest、Tag、Blob Metadata 检查。

Kubernetes Manifest、Secret、ConfigMap 分析。

Helm Chart、Terraform State 文件解析。

Cloud

AWS CloudTrail JSON / JSONL 分析。

IAM Policy、Role、AssumeRole、STS 事件关系图。

S3 Object Version、ACL、Bucket Policy 检查。

AWS、Azure、GCP 常见审计日志解析。

身份、资源、时间、源 IP 的关联分析。

ARN、Cloud Resource Identifier 解析。

Cloud Event 时间线、操作序列重建。

公共云配置文件格式校验和风险提示。

云环境在线查询可以作为可选连接，但日志文件和镜像的离线解析更适合你想做的工具箱。

20. E-mail & MIME Forensics
P1

此前规划了 EML / PST 等取证方向的部分外围工具，但没有专门的邮件解析工作台。实际上，邮件题中常见的步骤具有高度重复性：检查 Header、分析邮件路由、提取 MIME 附件、解码并计算 Hash。
GitHub

可以补：

EML / MBOX / PST / OST 导入（按格式逐步实现）。

RFC 5322 Header、MIME Multipart Tree。

Received Hop、时区、邮件路由时间线。

SPF、DKIM、DMARC Header 解析与结果显示。

Message-ID、From、Reply-To、Return-Path 对比。

Base64 / Quoted-Printable 附件提取。

HTML 邮件中的 URL、隐藏文本、远程资源检查。

邮件附件 Magic、Hash、嵌套文件分析。

PGP / S/MIME 结构解析。

生成可导出的 IOC / 证据摘要。

21. 其他具有明确题例的小型工具

以下适合直接加进已经存在的模块，而不必另建大型工作台。

新增能力

	

Writeup 中的实际场景




MIDI Note / Velocity LSB 提取

	

2025 年中文 Misc 题解中将 MIDI Velocity 最低位还原为字节 
博客园




Space / Tab / Newline 二进制映射

	

CTF@CIT 2025 Calculator 使用空格和 Tab 表达比特 
ctftime.org




音频频谱增强与图像导出

	

BroncoCTF 2026 Suspicious Remix 使用超声波频段中的频谱文字 
CTF Base




频谱 QR 图像恢复

	

2025 年 SWU CTF 将频谱图变换、修补后用于 QR 解码 
noonomyen




NTFS ADS / Zone.Identifier 解析

	

NUS Greyhats 2025 出现 ADS 隐藏数据题 
sl-lee.github.io




医学影像 DICOM 元数据与像素字段解析

	

2025 年 Misc Writeup 出现 .dcm 文件中的信息提取 
GitHub




透明 RGB 与动画帧联合扫描

	

openECSC 2025 Calamansi 
CTF Writeups




QR Error Correction 可视化

	

New Year CTF 2025 Broken QR 
ctftime.org

此外还可以预留更多低优先级格式适配器：3D 模型 OBJ/STL、电子电路网表、地理空间 GPX/KML、打印机指令、游戏录像、浏览器 HAR 文件，以及 OpenQASM / Quantum Circuit。

Quantum 也不是纯粹设想：2026 年 HTB 官方题解已经包含 Simon 算法、量子承诺等题型。不过这类工具建议归为长期扩展，不应抢占常用文件和协议工具的开发资源。
GitHub

三、还有三个我认为必须补上的底层能力

这三个不是某一道题专属的工具，而是能让前面几十个模块互相配合的基础设施。

22. Binary Structure Lab：自定义二进制协议与文件格式解析
P0，优先级非常高

很多 Writeup 都存在这样的步骤：先观察 Hex，推断字段偏移、长度、字节序，再写 Python struct.unpack() 解析，最后修改某个字段或重新构造数据包。

HKCERT CTF 2025 的 Protocol Fuzzing 就是典型案例：题解通过返回的错误信息，逐渐确定 Magic、Version、Message Type、Timestamp、Sequence、Payload Length 等字段，并用 Python 重新构造数据包。
GitHub

建议实现：

图形化定义字段：u8/u16/u32/u64、字符串、数组、枚举、位字段。

每个字段单独选择 Little / Big Endian。

支持固定长度、动态长度、条件字段、重复字段。

Hex Editor 与结构树双向高亮。

解析失败时指出字段、Offset 和预期长度。

修改字段后，自动更新相关长度、校验和。

自定义 CRC、Checksum、Padding、Alignment。

两份二进制文件按字段比较，而不只是逐字节 Diff。

自动导出 Python / JavaScript 的解析与序列化代码。

导入、导出 .ksy 格式描述。

这方面非常值得直接研究 
Kaitai Struct Web IDE
。它已经提供声明式二进制结构解析、Hex 与结构树联动，以及大量现成文件格式定义。2025 年发布的 Kaitai Struct 0.11 还增加了部分序列化支持，但并非所有语言和格式都能直接做到完整编辑后写回，因此编辑器部分要独立设计。
GitHub
+2

如果这个模块设计得好，以后甚至不需要为每一种特殊文件格式单独写解析器。

23. Remote Interaction Studio：远程交互题自动化
P0

此前规划了在线编译器和 Pwn 辅助，但遗漏了一个非常实际的日常需求：大量 CTF 题要求和远程程序进行多轮交互。

典型操作是：

连接 → 读取提示 → 提取数字 → 计算答案 → 发送 → 等待下一轮 → 重复

或者：

接收泄露地址 → 解析地址 → 计算偏移 → 构造 Payload → 发送

picoCTF 2025 PIE TIME 和 HKCERT 2025 Protocol Fuzzing 都体现了这种交互、状态跟踪、数据转换的模式。
GitHub
+1

建议做一个可视化的 pwntools 风格工作台：

TCP / TLS / UDP / WebSocket 连接。

ASCII / Hex / Raw Bytes 收发视图。

send、sendline、recvuntil、recvregex 等操作。

正则表达式提取远程响应变量。

根据变量自动计算下一次发送内容。

超时、断线重连、重试和会话重放。

多轮 Challenge 的状态机。

循环、条件分支、计数器。

自定义消息头、长度字段、序列号。

同一任务多次执行结果比较。

导出 Python / pwntools 脚本。

对输入输出做完整时间线记录。

浏览器无法直接建立任意原始 TCP 连接，因此这一部分需要后端网关或本地 Agent，并限制只能访问用户获授权的 CTF 目标。

24. Web Request Differential Lab：请求差分与漏洞复现实验
P1

之前虽然有 HTTP Request Builder，但 Web Writeup 中反复出现的过程通常是：只改变请求中的一个因素，对比服务器行为是否改变。

HTB Bug Bounty CTF 2025 的 Writeup 包含多种请求结构、参数处理、GraphQL、模板和应用逻辑方面的分析。
Whale120's Blog

建议提供：

两个或更多 HTTP 请求并排编辑、结构化 Diff。

自动枚举 Query、JSON、Cookie、Header 中指定字段的候选值。

自动比较 Status、响应长度、内容 Hash、JSON Path、耗时。

JSON / Form / Multipart / XML / GraphQL 不同输入格式转换。

参数增删、字段类型变化、重复参数测试。

URL 编码、大小写、路径正规化差异测试。

HTTP/1.1、HTTP/2、WebSocket、gRPC 请求结构查看。

OAuth、OIDC、SAML 的消息结构和状态流追踪。

认证前后、不同测试账号之间的请求差异。

请求和响应自动去除随机 Token、时间戳等噪声。

Race Condition 本地模拟、响应顺序可视化。

Burp Request / HAR / OpenAPI 导入导出。

重点是结构化对比、可复现测试、保存证据，而不是简单再做一套 Burp Suite。

四、把 Writeup 进一步抽象成通用操作

研究这些题解后，我认为应该把常见操作整理成下面这套可组合的“原语”。这比单独维护几百个工具页面更重要。

标准化操作

	

输入 → 输出

	

复用场景




Detect

	

文件 → 类型和候选解释

	

Misc、Forensics、Reverse




Extract

	

文件/流 → 指定字段或区间

	

PCAP、USB、PNG、日志




Carve

	

大文件 → 内嵌文件

	

固件、镜像、压缩包




Reassemble

	

离散片段 → 完整数据

	

DNS、TCP、分帧、USB




Permute

	

字节序列 → 重新排列的序列

	

Crypto、Reverse、Misc




Decode

	

编码数据 → 解码数据

	

几乎所有类别




Decompress

	

压缩数据 → 原始数据

	

Malware、Archive、Forensics




Parse

	

Bytes → 结构化字段树

	

文件格式、协议、逆向




Mutate

	

字段/数据 → 修改结果

	

文件修复、协议测试




Validate

	

产物 → 校验结论

	

CRC、格式、签名、Flag




Diff

	

多份数据 → 差异

	

图片、程序、日志、Web




Replay

	

交互历史 → 可复现过程

	

Pwn、Web、Oracle




Correlate

	

多来源证据 → 时间线/关系图

	

Forensics、OSINT、Cloud




Search

	

候选空间 → 满足约束的候选

	

密码、Nonce、CRC、参数




Visualize

	

原始数据 → 人能观察的图形

	

隐写、频谱、图像、硬件

例如前面提到的 2025 年 USB-HID Writeup 可以表达为：

PCAP → Extract USB Reports → Parse HID → Reassemble Key Events → Decode Keyboard Layout → Text

2025 年 Docker 镜像历史数据恢复，则可以表达为：

OCI Image → Parse Layers → Compare Whiteouts → Recover Previous File → Search Secret

这种设计还能允许用户在某一步手动选择候选，而不要求自动识别引擎从头到尾都猜对。

五、经过这次查漏补缺后的开发优先级

以下排序是根据检索到的实际复用场景、预计使用面、能否形式化、实现成本综合判断的产品优先级，而不是有统计样本支撑的全网使用次数排名。

优先级顺序

	

工具或子系统

	

主要原因




1

	

文件自动初检与内容提取

	

多数文件题的共同入口




2

	

Hex + Binary Structure Lab

	

通用于自定义格式与协议




3

	

USB-HID 还原

	

步骤高度标准化、手写脚本繁琐




4

	

网络字段提取和重组

	

DNS、ICMP、HTTP、自定义协议复用




5

	

多层脚本自动拆解

	

常见的重复解码/解压操作




6

	

Git 历史与悬空对象恢复

	

文件恢复路径清晰




7

	

PNG/BMP/QR 修复增强

	

图形化操作价值很高




8

	

Remote Interaction Studio

	

减少反复写交互脚本




9

	

压缩包结构及加密分析

	

ZIP、7z、RAR 等可复用




10

	

时间线与证据关联

	

适合复杂取证题




11

	

Mobile / Unity / Godot 资源提取

	

专用工具的 Web 化价值高




12

	

Crypto Oracle / Nonce Analyzer

	

可复用的数学及交互框架

如果还要增加一项横向能力，我建议是 Candidate Explorer：对每个可能的解码结果保留评分、理由、来源文件偏移和操作历史。这样出现几十条候选路径时，用户能知道为什么引擎认为某条路径有价值。

六、怎样继续系统性地挖掘遗漏

目前这轮检索可以确认许多真实题例，但还不足以把“高频”精确量化。下一步最有价值的不是继续漫无目的搜关键词，而是建立一个 Writeup → Operation 数据集。

我建议采用以下流程：

选择多个年份、比赛和题型的 Writeup，优先保留原作者和官方版本。

对每一篇提取工具、命令、输入格式、处理操作、输出格式。

将 tshark -T fields、Scapy 字段提取等相似命令归一化成 Extract Protocol Field。

去重转载内容，避免同一道题的多个复制版本抬高频率。

统计某操作出现在多少道不同题、多少场不同比赛。

分别计算适合纯浏览器、WASM、隔离后端的实现成本。

优先实现跨多个题型复用、且现有 Web 工具体验差的操作。

使用真实题目附件建立回归测试，确认工具能够复现 Writeup 中的关键中间结果。

对于工具功能本身，还要有一个明确的验收标准：不仅能读取数据，还应能重现实际题解中的某一步，并输出可直接进入下一步的数据。

七、这次研究最重要的参考入口

如果后续继续批量整理，可以优先从这些题解集合开始：

HTB Cyber Apocalypse 2026 官方题解
：新兴题型和综合分析案例。
GitHub

HTB Cyber Apocalypse 2025 官方题解
：传统题型与综合取证。

HKCERT CTF Challenges
：协议分析、密码学、Web 等题目及 Writeup。
GitHub

DownUnderCTF 2025 公开题目与题解
：可用于构造实际回归测试。

Kaitai Struct Formats
：现成二进制格式定义，可用于构建通用解析器。
GitHub

**结论：**你最开始的清单已经非常广，但它更多是在罗列“能用什么算法处理数据”。实际 Writeup 暴露出的需求是：用户要不断识别格式、提取字段、重组数据、执行脚本、观察结果、修复结构，并把中间产物继续交给另一个工具。

因此，新增二十多个专业工具模块固然有价值，但我会优先做一个能够共享文件、Bytes、结构化对象、Recipe、历史记录、执行沙箱的统一工作台。

这样未来新增一个特殊 CTF 解码工具，可能只是增加一个操作定义；新增一个文件格式，也可能只需要提供一份解析 Schema。这才是把大量 Writeup 中重复的手工操作真正产品化。

对于你这个结论，详细展开说一下，再往后设计
CTF Workbench：从在线工具箱到完整解题工作台

产品架构设计 v0.1 · 功能边界、核心引擎、工作流、插件系统与开发路线

我认为这个项目下一阶段应该停止按工具数量规划产品，转而围绕「一道 CTF 题目从拿到附件到得到 Flag 的全过程」设计系统。

这并不意味着取消原本的数百种独立工具。恰恰相反，这些工具全部保留，但它们只是更大系统的组成部分。

真正的产品目标是：

用户可以从任何一份文本、文件、图片、网络流量或二进制程序出发，持续进行识别、提取、变换、验证、分析和调试。每一步都保留数据、参数、结果和来源，任意中间产物都能继续进入其他工具，而不需要反复下载、上传、编写临时脚本。

最终，这个平台应该同时具备四种使用方式：

工具箱模式：快速做一次 Base64 解码、Bit Reverse、CRC 计算、PNG 高度修改。

分析工作台模式：导入一个题目，逐步检查附件，保存所有中间结果和线索。

流水线模式：像 CyberChef 一样组合操作，但支持多个输入、输出、分支和大型文件。

辅助求解模式：系统提出有证据的下一步建议，自动尝试有限范围内的候选转换，由用户判断和继续。

这四种模式应该共用完全相同的处理引擎，而不是开发四套系统。

一、先确定产品最核心的设计原则
1. 一切围绕 Artifact，而不是输入框

传统在线工具的基本交互是：

输入 → 操作 → 输出 → 复制 → 打开下一个工具 → 粘贴

我建议改成：

Artifact → Operation → Artifact

这里的 Artifact（数据产物） 是整个平台最重要的概念。

一个 Artifact 可以是：

一段文字或字节流。

一个 PNG、ZIP、ELF、PCAP 等文件。

图片中提取出来的一条 LSB 数据。

网络流量中重建出来的完整 TCP Stream。

一份 JSON、协议字段树、事件列表。

一个反编译得到的脚本。

一次程序运行产生的标准输出。

某个中间步骤得到的候选 Flag。

例如，一道 Misc 题可能产生这样的历史：

chall.png

原始 Artifact

用户导入的题目附件

PNG Structure Analysis

发现 IHDR 参数、CRC 或扫描行异常

repaired.png

根据用户选择的候选尺寸修复的新文件

LSB Extract — RGB / Bit 0

提取并重新排列像素中的最低有效位

extracted.bin

得到可继续分析的字节流

Detect → Decode

识别候选编码、解码并检查结果

Candidate Flag

保留匹配证据和完整操作历史；是否正确仍需验证

注意，这里的每一个文件和中间字节流都是独立、可预览、可下载、可继续处理的对象。

用户不应该因为关闭了某个工具页面就丢失处理结果。

2. 非破坏性操作是默认行为

任何修改都生成新的 Artifact，不直接覆盖原始输入。

例如：

PNG 宽度修改，生成修复后的 PNG。

头尾交换，生成新的字节流。

删除前 16 字节，保留原始文件。

Hex Editor 修改的内容先放在 Patch Overlay 中，导出时再生成新文件。

这样能自然实现撤销、重做、版本比较、分支探索。

3. 数据与它的表现形式必须分离

这是整个设计中最重要、也最容易做错的地方。

一段字节：

48 65 6C 6C 6F

可以被显示成：

Hex：48 65 6C 6C 6F

ASCII：Hello

Binary：01001000 01100101 ...

Decimal：72 101 108 108 111

作为某种二进制结构中的五字节字段

但它们不一定意味着发生了五次数据转换。

切换显示方式不应该修改底层字节。

我建议严格区分：

概念

	

行为

	

示例




View

	

只改变显示

	

Bytes 以 Hex 显示




Convert

	

显式转换数据类型

	

Hex 字符串解析为 Bytes




Transform

	

改变实际内容

	

XOR、Bit Reverse




Parse

	

解释结构

	

PNG Chunk、ELF Header




Analyze

	

产生发现、评分或候选

	

文件类型识别、隐写扫描




Execute

	

运行代码或外部工具

	

Python、zsteg、Binwalk




Validate

	

检验假设或结果

	

CRC、格式完整性、解压测试

这可以避免许多编码工具中经常出现的问题：用户以为进行了字节反转，实际上反转的是十六进制字符。

CyberChef 已使用带类型的 Operation，以及操作间的自动类型转换机制。我们可以借鉴它的操作抽象，但在 CTF 二进制分析场景中，更建议对有损、存在歧义的转换要求明确确认，例如字符串变字节时必须说明字符集。
GitHub

4. 原始数据、分析发现和候选结果要分开

例如识别到 PNG 文件内存在 ZIP Signature，系统不能直接断言“里面有一个 ZIP 文件”。

应当分别保存：

Artifact：原始文件。

Finding：在 Offset 0x1234 发现疑似 ZIP Signature。

Validation：ZIP 结构是否完整，能否解出文件。

Candidate：可以尝试从该位置 Carve 的产物。

Evidence：对应的字节范围、匹配规则、校验结果。

这样自动化引擎才不会因为匹配到偶然出现的 Magic Bytes，就进入错误的分析分支。

二、系统架构：我建议做成 7 层

不要一开始就搭一堆独立微服务。可以采用一个前端应用、一个共享核心引擎、一个可选的隔离计算后端，通过内部模块边界保持可扩展。

① 用户交互层

Quick Tools · Workbench · Pipeline · Code Lab

② Workspace & Artifact 层

项目、原始文件、中间结果、历史、派生关系

③ Operation Registry

所有工具的统一注册、参数、输入输出与能力声明

④ Analysis Engine

识别、分析发现、候选生成、验证、排序

⑤ Pipeline & Execution Engine

任务调度、DAG、缓存、取消、预算、执行路由

Browser

TS / Workers

WASM

Rust / Python

Backend

隔离容器

⑥ Persistence & Provenance

本地文件存储、内容哈希、操作历史、结果索引

⑦ Extension & Integration

插件 SDK · Kaitai Schema · 第三方工具适配 · Recipe 交换

这些是逻辑层，不代表要建立七个进程，也不意味着每个模块都需要自己的数据库。

1. Workspace：一个题目就是一个工作区

Workspace 内应保存：

对象

	

内容




Project

	

题目名称、分类、来源、备注




Artifact

	

文件、文本、提取结果、程序输出




Operation Run

	

工具 ID、版本、参数、输入输出




Finding

	

从文件中发现的可疑信息




Candidate

	

待验证的解释或结果




Pipeline

	

用户建立的处理步骤和分支




Note

	

用户写的分析笔记




Evidence Link

	

发现与来源的关联




Execution Record

	

执行状态、耗时、资源消耗、错误

例如用户上传一份 challenge.zip，它本身是一个 Artifact。解压出来的 capture.pcapng、secret.png 和 readme.txt 分别成为新的 Artifact，但仍然属于同一个 Workspace。

用户可以右键任何中间产物，选择“作为新输入打开”“比较”“运行分析”“添加到 Pipeline”。

2. Artifact Store：文件只保存一次，多处引用

绝对不要在每个工具之间反复执行：

const bytes = new Uint8Array(await file.arrayBuffer());

这会导致一个 500 MB 文件在多层工具之间不断复制，最终占用大量内存。

正确的做法是引入统一的 ByteSource：

interface ByteSource {
  readonly size: number;

  read(
    offset: number,
    length: number
  ): Promise<Uint8Array>;

  stream(
    start?: number,
    end?: number
  ): ReadableStream<Uint8Array>;
}

它背后的存储可以是：

用户刚刚拖入的 File。

浏览器本地 OPFS 中的数据。

另一个文件的一段 Slice。

从压缩包按需解出的数据。

WASM 工具生成的字节流。

后端任务返回的临时产物。

对外则暴露相同的接口。

大文件读取采用分块方式，Hex Editor 只加载当前窗口附近的数据，避免为了显示几行内容而读取整个文件。

浏览器原生的 Blob Streams、TransformStream 和 OPFS 已提供这些实现所需的主要基础能力。OPFS 适合保存应用私有的数据，但仍受到浏览器存储配额限制，也可能因用户清除站点数据而消失，因此必须提供完整项目导出。
MDN
+2

3. 数据模型采用“小核心 + 扩展类型”

不要一开始就为音频、视频、网络、磁盘、ELF、图片等定义几十个相互依赖的数据类型。

第一版核心类型建议只有：

类型

	

用途




Bytes

	

原始二进制数据、文件内容




Text

	

带明确字符编码语义的文本




Number

	

Number / BigInt / 定点或浮点数




Structured

	

JSON、记录、字段树、表格




Collection

	

多文件、多帧、多条数据




EventStream

	

网络包、键盘事件、日志事件

图片、音频和 ELF 最初都是 Bytes。只有解析之后，才产生对应的结构化视图或派生数据。

例如：

PNG Bytes → PNG Metadata → Image Pixels → Bit Planes → Extracted Bytes

PCAP Bytes → Packet Records → TCP Streams → HTTP Messages → Extracted Files

USB Reports → HID Events → Key Events → Reconstructed Text

每条边应明确输出类型，并禁止危险的隐式转换。

一个 PNG 即使被设置了 .txt 后缀，也应该保持原始 Bytes 不变；文件名、扩展名和 MIME 只是参考元数据。

4. Provenance：给每一步建立完整来源记录

我认为这才是整个项目最有长期价值的部分。

每个操作应记录：

interface OperationRun {
  id: string;

  operationId: string;
  operationVersion: string;

  inputArtifactIds: string[];
  parameters: Record<string, unknown>;

  outputArtifactIds: string[];

  status:
    | "success"
    | "partial"
    | "failed"
    | "cancelled";

  startedAt: string;
  finishedAt?: string;

  runtime?: string;
  diagnostics?: string[];
}

真正存储时，还应记录输入内容哈希、执行引擎版本、随机种子和适用的环境信息。

作用主要有五个：

任意结果都能回溯完整来源。

重复执行相同确定性操作时，可以复用缓存。

操作出现 Bug 后，能知道哪些历史结果受影响。

用户可以导出完整 Recipe。

后续能用真实处理过程建立回归测试。

还建议加入 Source Span。

例如在 Hex Editor 中点击一个 PNG Chunk，能够反向高亮它在原始文件中的 Offset。一个二进制格式字段可以携带：

sourceArtifactId + startOffset + length

并非所有变换都存在精确的字节映射。压缩、哈希、复杂加密后，应该保留操作级来源关系，而不是伪造一一对应的 Offset。

三、Operation Engine：让所有工具使用同一个协议

假设你要实现 Bit Reverse、Base64 Decode、PNG Chunk Parser、USB HID Decoder 和 RSA Solver。

这些看起来完全不同，但其实都可以抽象为：

声明能力 → 验证参数 → 获得输入 → 执行 → 返回产物和分析信息。

一个具体的操作定义

以下是我建议的 SDK 草案，不是现有第三方库的接口。

interface OperationSpec {
  id: string;
  version: string;

  title: string;
  category: string;

  inputs: {
    name: string;
    type: string;
    required?: boolean;
    multiple?: boolean;
  }[];

  outputs: {
    name: string;
    type: string;
  }[];

  parametersSchema: object;

  execution: "browser" | "wasm" | "remote";

  deterministic: boolean;
  streaming: boolean;

  capabilities: string[];
  estimatedCost?: "low" | "medium" | "high";
}

例如字节反转：

const reverseBytes: OperationSpec = {
  id: "bytes.reverse",
  version: "1.0.0",

  title: "Reverse Bytes",
  category: "binary",

  inputs: [
    { name: "data", type: "bytes", required: true }
  ],

  outputs: [
    { name: "result", type: "bytes" }
  ],

  parametersSchema: {
    type: "object",
    properties: {
      groupSize: {
        type: "integer",
        minimum: 0
      }
    },
    required: ["groupSize"],
    additionalProperties: false
  },

  execution: "browser",
  deterministic: true,
  streaming: true,

  capabilities: [],
  estimatedCost: "low"
};

约定 groupSize=0 代表整个字节序列反转，正整数代表按该字节宽度分组反转。分组规则和不足一组时的行为，也需要在正式协议中明确。

这里仅定义操作元数据，实际的 run()、读写器、任务取消与异常处理由 SDK 提供。

Operation Registry 应该负责什么？

功能

	

作用




ID 与版本管理

	

保证 Recipe 可以复现




输入输出检查

	

阻止不兼容的操作连接




JSON Schema 参数校验

	

自动生成表单和参数校验




执行引擎选择

	

Browser / WASM / Remote




搜索和分类

	

根据关键词、输入类型推荐工具




资源预算

	

控制输入规模、时间、内存




权限检查

	

网络、代码执行、文件访问




结果缓存

	

避免重复运行




扩展注册

	

添加新工具而不改 UI 核心

Operation 不应该负责 Workspace 页面、文件选择弹窗、历史面板或下载按钮。

这些全部由平台统一提供。

操作系统还应支持几个高级属性

**可逆性：**明确操作是否有逆变换。例如 XOR 使用同一个密钥可逆，Hash 不可逆，UTF-8 解码对非法序列可能不可逆。

**纯函数性质：**输入和参数相同，输出是否一定相同。依赖系统时间、远程 API 或随机数的操作，需要保存环境或 Seed。

**流式处理能力：**是否能够按块读取和输出。对于 Base64、UTF-8、分组反转等，需要正确处理跨 Chunk 的边界，不能简单地把每个 Chunk 独立执行。

**副作用：**是否需要网络请求、执行代码、产生临时文件。自动分析引擎绝不能未经授权触发存在外部副作用的操作。

**部分成功：**解析器即使遇到损坏文件，也应该允许返回已经解析成功的字段和错误位置。Kaitai Struct Web IDE 已将这种 Partial Parsing 用于二进制格式调试，是非常值得借鉴的设计。
kaitai.io

四、Pipeline Engine：从线性 Recipe 进化成 DAG

CyberChef 的 Recipe 非常适合线性处理，但完整 CTF 解题经常不是一条直线。

比如同一份 PCAP 可能同时产生：

DNS Exfiltration 数据。

HTTP 下载文件。

USB HID 记录。

多条 TCP Stream。

可疑域名和 IP。

其中某条流量还可能需要 XOR、解压或者按序列号重组。

因此我建议 Pipeline 采用 DAG（有向无环图）。


flowchart TD
    A["导入 PCAP"] --> B["解析协议"]
    B --> C["DNS 字段提取"]
    B --> D["HTTP 对象恢复"]
    B --> E["USB HID 提取"]
    C --> F["按顺序重组"]
    D --> G["内嵌文件扫描"]
    E --> H["键盘事件重建"]
    F --> I["自动候选解码"]
    G --> J["文件分析"]
    H --> I
    I --> K["候选结果"]
    J --> K
Pipeline 应支持的节点

节点类型

	

行为




Source

	

文件、文字、URL 响应、外部导入




Transform

	

编码解码、排列、XOR、压缩




Extract

	

提取字段、Offset、文件、记录




Parse

	

文件格式、协议、结构化解释




Analyze

	

检测规则、Entropy、Signature




Validate

	

校验结果、排除错误候选




Branch

	

从同一输入分出多条路径




Filter

	

按条件筛选数据




Map

	

对多个 Artifact 分别执行




Merge

	

拼接、聚合、合并结果




Iterate

	

有预算的重复处理




Script

	

执行用户提供的程序




Export

	

下载、保存、提交给其他工具

这里有个值得坚持的设计：DAG 是静态依赖图；循环和自动探索必须由单独的受限迭代节点管理。

不要让任意两个节点互相连成无限循环，否则任务取消、缓存和错误追踪都会变得很复杂。

Pipeline 保存格式

推荐 JSON 作为底层格式，UI 再提供可视化节点编辑。示意：

{
  "schemaVersion": 1,
  "name": "XOR Decode",
  "nodes": [
    {
      "id": "source",
      "op": "input.artifact",
      "params": {}
    },
    {
      "id": "xor",
      "op": "bytes.xor@1.0.0",
      "params": { "keyHex": "23" }
    },
    {
      "id": "decode",
      "op": "text.decode@1.0.0",
      "params": {
        "encoding": "utf-8",
        "onInvalid": "error"
      }
    }
  ],
  "edges": [
    {
      "from": "source.output",
      "to": "xor.data"
    },
    {
      "from": "xor.result",
      "to": "decode.data"
    }
  ]
}

这里的 input.artifact 是运行时绑定输入，不必把文件本体编码到 JSON。

以后可以直接把这个 JSON 做成命令行可执行的 Recipe，甚至在 CI 里对测试样本回归验证。

Pipeline 执行策略

第一版我建议这样设计：

节点默认按依赖顺序执行。

没有依赖关系的节点可以并行。

相同输入、参数、版本的确定性节点可使用缓存。

修改上游数据后，仅让受影响的下游节点失效。

允许单节点重新运行，不强制重跑整条 Pipeline。

单个节点失败后，保留此前的所有中间 Artifact。

每个节点分别展示耗时、状态和错误。

支持暂停后继续人工调整，但不隐式恢复已产生副作用的远程操作。

任务可以取消，并释放对应 Worker / 后端资源。

对于输出非常大的节点，可以提供 Lazy Materialization：只在需要预览、下载或被下游使用时生成完整结果。

这样既能提高性能，也能避免把所有扫描候选都复制保存一遍。

五、Analysis Engine：真正有差异化价值的部分

这里我想进一步区分三个概念：

Detector：判断输入可能是什么。

Analyzer：检查它有什么特征、异常或值得关注的内容。

Explorer：根据这些信息尝试下一步操作，并验证候选结果。

不应该把三者混为一个“AI 自动解题”按钮。

1. 自动分析应分成五个阶段

阶段 A：快速初检（Cheap Scan）

读取文件头、尾及必要的采样区域，检查 Magic、扩展名、长度、字符集、可打印字符、典型编码特征和简单熵分布。

阶段 B：格式专用检测（Structural Scan）

根据候选格式运行轻量解析器：PNG Chunk / CRC、ZIP Directory、ELF Header、PCAP Header、PE、SQLite、PDF、Gzip 等。

阶段 C：提出可解释的建议（Hypotheses）

例如 PNG 文件高度字段异常，建议校验扫描行；文件尾存在疑似 ZIP 结构，建议 Carve；文本满足 Base64 字符集和长度约束，建议试解。

阶段 D：有限自动探索（Candidate Search）

对低成本、无副作用的操作尝试有限的候选参数，生成分支，继续识别解出的新数据。

阶段 E：验证、排序、交给用户（Verification）

根据结构完整性、解压成功、CRC、文本合理性、预期模式等证据，对候选进行排序和解释。

CyberChef Magic 已采用模式匹配、推测执行、文件 Magic、UTF-8、熵和字符频率等方法，对候选解码路径进行递归探索。我们可以沿用这些成熟的思路，把探索结果进一步升级成可持久化的 Artifact Graph。
GitHub

2. 自动分析应该输出 Findings，而不只是结果

例如导入一份文件，分析面板可能显示：

sample.bin

示意结果

识别到 PNG Signature

Offset 0x00000000 · 8 Bytes · 已匹配完整签名

IHDR CRC 校验不通过

建议检查尺寸字段及其他 IHDR 内容

文件尾检测到疑似 ZIP 结构

Offset 0x00004F20 · 需要进一步检查目录结构

可尝试的下一步

PNG 扫描行分析 · CRC 候选搜索 · 文件雕刻

用户点击任意 Finding，可以跳转到 Hex Editor 对应字节区域。

同时，该 Finding 还能直接作为后续 Operation 的输入条件。

3. 候选结果如何评分？

我不建议第一版做一个看似精确的“成功概率 96.7%”。

可以采用明确的证据维度：

维度

	

可以验证什么




Signature

	

是否匹配已知文件格式




Structure

	

格式字段是否符合规范




Integrity

	

CRC、Checksum、签名等是否通过




Decode

	

是否完整解码或解压




Plausibility

	

字符分布、语法或结构是否合理




Target Match

	

是否匹配指定文本或 Flag 模式




Consistency

	

多条线索是否相互支持

第一版把发现分成“强证据 / 一般证据 / 弱线索”已经足够。

其中要特别注意：

高熵不等于加密，压缩数据也可能高熵。

出现 PK 不意味着一定存在完整 ZIP。

匹配 Flag 正则不代表答案正确。

CRC 匹配只能支持相应校验结论，不能证明文件完整。

成功解压不代表解出来的内容就是题目答案。

4. 自动搜索必须有预算

如果你让系统自动组合所有解码器、字节排列和 XOR 参数，候选路径会爆炸式增长。

因此应采用受限的 Beam Search 或其他有界搜索策略。

第一版可提供以下初始配置，具体默认值再通过基准测试调整：

预算项

	

初始建议




自动解码深度

	

3 层




活跃候选上限

	

100




单轮搜索时间

	

5 秒




自动探索总处理数据量

	

128 MiB




单次分支后保留候选

	

20




有副作用操作

	

默认禁止




自动联网 / 上传原文件

	

默认禁止

同时通过输入哈希、操作 ID 和参数去重，避免重复走相同路径。

分析模式分为三个等级比较合适：

Quick Scan：少量读取，不尝试复杂爆破。

Deep Scan：执行完整格式检查、更多特征识别。

Explore：尝试有界候选解码、参数枚举和分支搜索。

这样既能保留一键操作的便利，也不会让用户每次打开一个 1 GB 文件都触发大量后台计算。

六、界面设计：尽量减少工具之间的切换成本

我建议在产品中清晰区分“快速工具”和“完整工作台”。

1. Quick Tools：保留传统在线工具的优势

例如用户只想把一段 Hex 转 ASCII，应该可以进入首页，直接搜索 hex，粘贴，立即得到结果。

不能强制创建 Project，不能必须打开 Pipeline，也不应该要求用户理解 Artifact。

但是每个快速工具都应有：

输入和输出的类型显示。

一键交换输入输出（可逆且有定义时）。

直接将结果送入另一个工具。

打开到 Workbench。

将操作添加到 Recipe。

下载文件、复制文字和查看 Hex。

查看操作的具体参数与错误。

这是吸引普通使用者最重要的入口。

2. Workbench：真实解题时的主界面

桌面端建议采用这样的布局：

Workspace / Challenge

文件 / 产物

chall.png

repaired.png

extracted.bin

notes.txt

工具

Search...

Hex

Image

Structure

00000000 89 50 4E 47 0D 0A 1A 0A

00000008 00 00 00 0D 49 48 44 52

00000010 00 00 01 90 00 00 02 58

00000018 08 06 00 00 00 12 34 56

文件当前视图 · 选择字段可联动右侧 Findings

Findings

PNG Signature

CRC Mismatch

建议操作

Repair IHDR

Analyze Scanlines

操作历史 / Pipeline

Import

PNG Parse

Repair

LSB Scan

交互布局概念示意，不是已经实现的页面。

桌面大屏可以采用上述三栏布局，窄屏则折叠成文件列表、主视图、分析结果三个独立面板。

3. 每种 Artifact 使用合适的 Viewer

输入类型

	

默认 Viewer




文本

	

Monaco / Text Editor




原始字节 / 文件

	

Hex Editor




PNG / JPEG / BMP

	

Image Viewer + 像素分析




JSON / XML

	

Tree Viewer




PCAP

	

Packet Table + Stream Viewer




ELF / PE

	

Binary Structure Viewer




WAV / MP3

	

Waveform + Spectrogram




CSV / SQLite

	

Table Viewer




Git 仓库

	

Commit Graph + File Tree




多帧图片

	

Frame Timeline




事件日志

	

Timeline + Filter




多个候选结果

	

Candidate Explorer

所有文件都保留一个基础 Hex 视图作为兜底。

4. 打通所有 Viewer 的联动

这会带来非常明显的体验提升。

比如 PNG Structure Viewer 中点击 IHDR.height：

Hex Editor 自动定位高度字段。

显示 Little / Big Endian 解释（PNG 字段按规范解析）。

显示实际字段值。

关联 CRC 校验结果。

可以打开候选修改面板。

修改后生成新的文件 Artifact。

自动重新运行受影响的分析步骤。

PCAP 中点击 TCP Payload 也一样，可以直接把这段 Payload 送到 Hex、Text、XOR、解压工具。

真正优秀的工作台应该让用户操作“数据”，而不是费力寻找“工具页面”。

七、执行引擎：浏览器优先，但不能强行全部放浏览器

我建议平台支持三种运行环境，以及一种可选的远程交互网关。

运行环境

	

负责什么

	

何时使用




Browser Worker

	

常规 TS 操作、文本、编码、简单文件解析

	

默认




WASM Worker

	

高性能二进制分析、压缩、计算密集型算法

	

按需加载




Isolated Runner

	

多语言编译、复杂取证、原生工具、动态分析

	

确有需要时




Remote Gateway

	

授权 CTF TCP/TLS、HTTP 等远程交互

	

用户主动连接

1. 浏览器负责多数日常操作

包括编码、Hash、Bit/Byte、文件头、PNG/BMP、基本隐写、Hex Editor、文本分析、数学计算等。

Web Workers 负责防止重计算阻塞 UI，但Web Worker 不是恶意代码的安全隔离边界。Worker 仍可使用部分网络和存储 API，所以可信的内置算法与用户上传的任意代码必须分开处理。
MDN
+1

2. WASM 不应从第一天覆盖所有操作

建议只有遇到以下情况才引入 Rust/WASM：

纯 TypeScript 的性能达不到要求。

已存在成熟可靠的 Rust/C/C++ 解析器。

需要复用专业取证或密码学实现。

特定算法有大量位操作或数据处理。

例如 Binwalk v3 是 Rust 实现，提供签名检测、文件提取与熵分析，可以研究其 Rust 库的集成方式；但它的完整提取能力存在外部程序依赖，不能假设直接编译成 WASM 就拥有完整功能。
GitHub

3. 后端要有真正的运行隔离

当你加入在线 Python、C++、Ghidra、SageMath、程序动态分析时，就必须建立隔离运行环境。

后端最低应实现：

每个用户任务拥有独立的运行环境。

CPU、内存、磁盘、执行时间限制。

无特权用户执行。

只读基础镜像、受限临时工作目录。

默认无外网连接。

不允许访问宿主机内部服务与其他用户任务。

输入文件按需挂载或复制。

任务结束后销毁隔离环境。

不记录用户敏感原始文件到普通日志。

运行状态、错误、资源限制结果可查询。

公开提供不可信代码执行时，建议评估 gVisor 或 Firecracker 这类强化隔离方案，而不只是普通 Docker 容器。gVisor 提供用户态应用内核，Firecracker 则基于轻量虚拟机。两者的成本、兼容性和安全边界不同，需要实际测试。
gVisor
+1

4. 本地优先应成为产品的公开承诺

默认行为：

用户上传文件到网页 ≠ 文件上传到你的服务器。

文件首先在浏览器里处理。只有某个操作确实需要后端时，才明确展示将发送什么数据，以及任务所需的能力。

可以提供三个执行策略：

Local Only：绝不向服务器传送文件内容。

Prefer Local：优先浏览器，需要远程执行时询问。

Allow Remote：允许用户批准的隔离后端任务。

项目共享默认只分享操作 Recipe，不分享真实输入、密钥或文件内容。

八、插件系统：未来工具如何以极低成本接入？

我建议插件分三层，而不是设计一个复杂的全能插件 API。

第一层：Operation Plugin

适合：

Base64、Hex、ROT。

自定义 XOR、CRC。

特殊文本映射。

小型数学求解。

文件字段提取。

插件只实现数据处理、参数定义与测试。

不允许直接操作 UI 或任意访问整个 Workspace。

第二层：Format Plugin

适合：

PNG、BMP、ZIP。

ELF、PE、PCAP。

DICOM、游戏资源。

自定义协议。

Format Plugin 负责检测、解析、结构验证和支持的导出能力。

优先研究 Kaitai Struct 的 .ksy 描述语言和现有格式库。它已经能将格式描述生成 JavaScript 等语言的解析器。需要注意，官方 v0.11 文档中的写入支持主要针对 Java 和 Python，不能把读取解析和完整的浏览器端编辑序列化视为同一项现成能力。
kaitai.io
+2

我建议第一版的文件修改使用独立 Patch Engine：

Parsed Structure → Field Change → Patch Validation → Recalculate Dependencies → New Artifact

例如修改 PNG 的 IHDR，并自动重新计算 CRC；这种功能无需让整个 Kaitai Schema 都支持双向序列化。

第三层：Tool Adapter

适合接入已经成熟的程序：

zsteg

binwalk

exiftool

tshark

ffmpeg

RsaCtfTool

SageMath

Ghidra

Volatility

pwntools

Adapter 应描述命令能力、参数、运行时依赖、输出格式、资源限制，并将输出转换为平台 Artifact 和 Finding。

这样不必为每一个复杂工具重新实现算法。

但也不要允许不可信第三方插件在网页主 Origin 中获得完整权限。第三方插件必须经过权限控制和隔离，且需要审查各个依赖及格式 Schema 的许可证。

为什么要把三层分开？

因为它们解决的问题不同。

Operation 负责变换数据，Format 负责理解数据，Adapter 负责复用现有程序。

如果混在一起，以后加入一个新的图片格式可能不得不修改文件存储、UI、工作流和执行器。反过来，这三种插件分开以后，新增格式通常只需注册检测与解析逻辑。

九、把真实 CTF Writeup 变成开发和验证资料

我认为这是项目后期最值得投入的长期工程。

前面已经整理出大量 Writeup 中反复出现的处理步骤。下一步应该建立一个结构化的 CTF Operation Corpus。

不是为了直接训练一个“自动做题 AI”，而是为了回答三个问题：

竞赛中真正反复使用哪些操作？

哪些操作已经有可靠工具，哪些仍要反复手写代码？

我们的新工具能不能完整复现实际解题过程？

每篇 Writeup 的结构化记录
challenge:
  id: sample-usb-001
  category: forensics
  input_formats:
    - pcapng

steps:
  - operation: pcap.parse
    output: packets

  - operation: usb.extract_hid_reports
    input: packets
    output: hid_reports

  - operation: hid.keyboard_decode
    input: hid_reports
    output: key_events

  - operation: hid.reconstruct_text
    input: key_events
    output: text

verification:
  expected_type: text
  expected_pattern: "flag\\{.*\\}"

这里是规范示意，不对应某道具体比赛的原始文件。

每个步骤还可以记录原作者使用的工具、命令、参数、真实输入输出文件、来源 URL，以及可否合法用于自动化测试。

反过来推动开发

比如收集到 100 道不同的文件取证题，可以计算：

有多少道涉及 Magic 检测？

有多少道涉及字段提取？

有多少道涉及多次解压？

有多少道涉及排列、XOR？

有多少道使用了 Python 临时脚本？

哪些脚本其实可以归一化成一个通用 Operation？

同一道题的转载和多个版本需要去重，避免误判工具使用频率。

最终，新增一个功能不只是添加一个按钮，而是可以明确说：它能取代哪些实际 Writeup 中反复出现的手工步骤。

每种成熟的 Operation 最好拥有：

正常输入测试。

异常输入测试。

边界和大文件测试。

随机测试或属性测试。

真实 CTF 题目的回归样本（在授权及许可允许时）。

这样工具覆盖范围会随着项目发展不断变得更可靠，而不是只增加数量。

十、技术栈与代码组织

对于第一版，我建议尽可能少引入语言、服务和抽象。

组件

	

推荐选择

	

原因




前端

	

React + TypeScript + Vite

	

组件生态成熟




UI

	

Tailwind CSS + 自建工具面板

	

可快速统一交互




代码编辑器

	

Monaco Editor

	

适合代码、文本、Hex 相关功能




DAG 编辑器

	

React Flow

	

节点、连线、保存恢复支持成熟




简单 Operation

	

TypeScript

	

迭代成本低




重型本地处理

	

Rust → WASM，按需加入

	

兼顾性能和复用




本地文件

	

OPFS + File API

	

浏览器内保存和读取




本地元数据

	

IndexedDB

	

Workspace、历史、配方




高级 Python

	

Pyodide / 隔离后端

	

依据依赖和安全需求选择




后端 API

	

TypeScript + Fastify（后期）

	

与前端保持语言统一




重型工具

	

独立 Python / 原生 Runner

	

利用成熟生态




共享存储

	

需要多用户时再引入

	

避免过早架构复杂化

React Flow 目前已有节点状态保存和恢复的官方实现示例。Pyodide 也正式支持放在 Web Worker 中运行，但 Python 代码仍应根据权限和安全需求决定执行环境。
React Flow
+1

建议项目目录：

ctf-workbench/
├── apps/
│   └── web/
│
├── packages/
│   ├── core/             # Artifact、类型、通用协议
│   ├── engine/           # 执行器、DAG、缓存、预算
│   ├── operations/       # 内置工具
│   ├── analysis/         # Detector、Finding、Explorer
│   ├── formats/          # 文件结构解析
│   └── viewers/          # Hex、Image、Tree、PCAP 等
│
├── services/
│   └── runner/           # 后期再实现
│
├── tests/
│   └── fixtures/         # 回归样本
│
└── docs/

这是一种建议边界，而不是要求初期就发布所有独立 npm Package。开始时仍然可以在同一个 Monorepo 内开发；只有依赖和发布需求真实出现时才拆分。

十一、分阶段实施：先做完整链路，不先做几百个工具

我建议把开发划分为六个里程碑。

01

M0：核心数据与操作引擎

Artifact、ByteSource、Operation Spec、基础 Registry、数据类型转换、分块读取、Worker、统一错误机制。

完成标准：能够导入文件、执行多种操作、保存结果，原始文件不被修改。

02

M1：Quick Tools + File Workbench

优先做 Base、Hex、ASCII、Byte Operations、XOR、Hash、文件提取、Hex Editor、PNG/BMP 基础结构。

完成标准：用户能够完成一条跨多个工具的真实文件分析链路，而不是只能使用独立的小工具。

03

M2：Workspace + Provenance + Recipe

项目存储、历史记录、非破坏性 Patch、派生关系、线性 Recipe、导入导出。

完成标准：刷新页面后可继续工作，保存的 Recipe 可准确复现数据变换。

04

M3：自动分析 + DAG Pipeline

Detector、Finding、Candidate、验证器、候选搜索、分支处理、缓存和任务预算。

完成标准：系统能够解释为什么推荐某项操作，用户可以接受、拒绝或调整候选路径。

05

M4：专业分析器扩展

USB-HID、Git Forensics、PCAP Reassembly、PNG/QR 修复、高级文件雕刻、脚本解混淆。

完成标准：各专业模块共用 Artifact / Pipeline，不创建独立的文件和历史系统。

06

M5：隔离 Runner + 高级能力

在线编译、复杂 Crypto、逆向、取证、Pwn、外部工具、更多插件和可选团队工作区。

完成标准：执行沙箱有独立安全验收，客户端数据默认不因新增后端而自动上传。

特别建议：M0 与 M1 用一个真实题型做纵向验证

我建议第一个完整切片就选 PNG/BMP 文件修复 + Bit/Byte 操作 + LSB 提取。

因为它能一次验证系统最核心的架构设计：

文件作为 Bytes 导入。

通过 Format Plugin 解析结构。

通过 Finding 报告异常。

用户修改字段，创建新的 Artifact。

自动更新 CRC 或校验相关结构。

使用 Image Viewer 预览结果。

运行 LSB 提取，产生新 Bytes。

使用通用解码 Operation 继续分析。

保存完整历史、导出 Recipe。

重新打开 Workspace 后恢复工作。

如果这一条链路顺利跑通，说明 Artifact、Operation、Format、Viewer、Pipeline、Provenance 之间的协作基本成立。

相比一开始实现 200 个编码器，这个切片能更早发现真正的架构问题。

十二、我建议明确写进验收的技术指标

以下是建议的工程目标，尚不是实际测得的性能。

维度

	

建议验收标准




正确性

	

常用编码、位操作与成熟参考实现结果一致




无损性

	

Bytes → Hex View → Bytes 不发生非预期修改




可复现性

	

相同输入、固定参数和版本，确定性操作产生相同内容




大文件

	

100 MiB 文件可以分块查看，不必整体加载内存




可取消性

	

耗时任务可取消，UI 不因同步长任务失去响应




非破坏性

	

修改任何数据时原始 Artifact 保持不变




Pipeline

	

只重算失效节点，保留有效缓存




自动分析

	

Finding 与 Candidate 具有可查看的证据和来源




容错

	

损坏文件能返回已解析的部分结果及异常位置




隐私

	

Local Only 模式不发送用户文件内容




安全

	

ZIP Bomb、恶意脚本、异常结构不能无限占用资源




持久化

	

Workspace 可导出、重新导入并恢复历史




版本兼容

	

旧 Recipe 可以被迁移或明确指出缺失的 Operation 版本

另外还需要专门测试输入非常小、非常大、空文件、截断文件、非法 Unicode、非整字节排列、错误 Chunk Length、无效 CRC 等边界情况。

对于校验和、解压缩、加密、文本解码等操作，应当把失败状态与普通输出严格区分，不能把“解析失败返回空结果”误当作解码成功。

十三、再往后：从工具工作台进化到智能分析助手

到了 M4/M5，系统已经有了结构化的操作注册表、可靠的历史记录、结果验证器和自动候选搜索。

这时再考虑引入 LLM / Agent 才比较合理。

我不建议让 AI 任意写代码，然后在服务器上无限尝试。

更好的路线是把 AI 的职责限制在提出分析计划、解释发现和选择经过验证的工具。

阶段 A：基于规则的下一步推荐

例如用户导入 PCAP：

系统检测出 DNS 记录中存在大量长子域名，同时这些子域名只使用有限字符集。

推荐：

“提取 DNS Query Labels，并尝试按时间排序、拼接和解码。”

这一步可以完全没有 AI。

阶段 B：自动生成 Pipeline 草案

用户提出：

分析这个流量文件，看看有没有隐藏传输的文件。

系统结合检测结果，提出：

PCAP → DNS Extract → Reassemble → Base64 Decode → Magic Scan

用户可以预览并执行。

阶段 C：Agent 辅助分析

模型可以使用 Operation Registry 的能力描述，读取当前 Artifact 的摘要、结构和 Findings，选择下一步操作。

但应遵循：

优先使用已注册、可验证的操作。

明确声明分析目标和预算。

任何外部连接、后端运行或数据上传需要授权。

每次操作保留输入、参数和结果。

自动分析不应宣称未经验证的 Flag 已正确。

模型产生的解释与工具实际验证结果区分存储。

对于比较罕见的题型，模型也可以编写一次性的解析脚本，但必须在明确隔离的运行环境里执行，而不是把生成代码直接注入前端主应用。

阶段 D：Writeup-to-Recipe

这是长期很有潜力的扩展：

用户上传一篇 Writeup，平台识别其中的命令、代码块和处理步骤，将它们映射为标准 Operation，再产生一条待审查的 Pipeline。

如果 Writeup 中的步骤有对应数据和合法可用的附件，还可以尝试复现并生成回归测试。

这个功能不会保证自动把所有文章转换成可执行工作流，但能够持续积累可复用的处理方案。

阶段 E：CLI、API 和生态系统

等平台核心成熟，可以进一步提供：

浏览器操作与 CLI 共用同一套 Operation ID。

Headless Recipe Runner。

Python / TypeScript SDK。

第三方工具适配器。

可分享的 Recipe Library。

公共 Format Schema Registry。

可下载的 Workspace 项目包。

CTF 题目专用分析模板。

与 OI/ACM Code Lab 共用在线执行、文件管理、任务和可视化基础设施。

这样它就不再局限于 CTF 工具箱，还可以成为通用的二进制与数据分析平台。

十四、必须克制的范围

我建议第一阶段明确不做以下内容，以避免主架构迟迟不能落地：

不做完整的 CTF 在线判题平台。

不做支持所有语言的在线 IDE。

不做全自动解出任意 CTF 题目的 AI。

不重写 Ghidra、Wireshark、FFmpeg、SageMath。

不做公开第三方插件市场。

不提前引入 Kubernetes、复杂微服务和多租户云存储。

不追求第一版覆盖全部文件格式。

不把所有类型的分析结果强行统一为一种 JSON 结构。

第一阶段真正要完善的，是 Bytes、Artifact、Operation、Format、Viewer、Finding、Pipeline、Provenance 这些最基础的系统边界。

十五、最终产品应该形成怎样的体验？

理想的流程是这样的：

用户从比赛平台下载 challenge.zip，打开 CTF Workbench，把文件拖进去。

系统识别压缩包，列出内部文件，检查是否存在加密、尾随数据和异常结构。用户选择其中的 PNG。

PNG Viewer 显示图像，Structure Viewer 提示 IHDR 的某些字段异常。用户点击提示，Hex Editor 高亮对应字节，同时查看修复候选。

用户选择一个候选高度，系统生成 repaired.png，保留原始文件，重新运行结构验证。新图像能够正常显示，于是用户继续打开 Bit Plane 面板。

系统发现某种像素通道和读取顺序产生了具有文件签名的数据。用户选择导出这段数据，它立即成为 Workspace 中的新 Artifact。

检测器确认可以尝试解压。解压后出现文本和疑似 Flag。整个过程中没有反复下载文件，也没有重新上传到别的在线平台。

最后，用户可以直接导出：

修复后的图片。

提取出的二进制文件。

最终文本结果。

完整操作 Recipe。

文件与操作的派生关系。

一份包含验证结果的分析报告。

而且下次打开相同项目时，用户仍然能从任何中间步骤继续，不必重新进行全部操作。

我建议现在锁定的架构决策

首期架构基线

产品核心	Artifact-first Workbench
数据底层	Immutable Artifact + ByteSource
工具协议	Typed, Versioned Operation
自动分析	Detector → Finding → Candidate → Validation
工作流	先线性 Recipe，后 DAG
格式处理	Schema Parser + 独立 Patch Engine
运行环境	Local-first，按需 WASM / Backend
首个完整切片	PNG/BMP + Binary + LSB
验证体系	Golden Vectors + 真实 Writeup 回归

我最建议投入精力的不是“实现更多单独的工具”，而是让一个工具的输出自然成为另一个工具的输入，并让整个过程可以追踪、验证、修改和复现。

下一步的工程设计重点应当放在五份相互衔接的详细规范上：Artifact & Storage、Operation SDK、Pipeline Executor、Analysis & Candidate Engine、Workbench UI。其中前两份必须先稳定，后面的专业工具才能真正做到低成本扩展。

一旦这套底座成立，OI/ACM 的数据生成、对拍、反例缩减，以及 CTF 的二进制分析、隐写和取证，都可以复用同一套数据、执行和工作流基础设施，而不用每增加一个赛道就重新建立一整套平台。

Thursday 4:00 PM
我计划做的是全前端web，不涉及服务端计算。最好能完全cdn静态托管

这个约束非常关键。我建议据此重新确定整个项目的架构，而不是在之前的方案上简单删掉后端部分。

你的目标可以明确为：

一个 100% Client-Side、Local-First、可由 CDN 纯静态托管的 CTF / OI / ACM 综合工具工作台。

所有解析、计算、编解码、文件修复、隐写分析、代码执行及工作流处理，都在用户自己的浏览器中完成。服务器仅负责分发 HTML、JavaScript、CSS、WASM 等静态资源，不参与计算，也不接收题目附件。

这个方向是可行的。而且针对 CTF 里的 Misc、Crypto、Stego、Forensics、Reverse 静态分析，能覆盖相当多的实际需求。

最重要的架构调整有四个：

彻底取消 Backend Runner，将所有执行能力收敛到 Web Workers、WebAssembly 和浏览器隔离环境。

以浏览器文件系统为核心，文件不上传、不经服务器中转，所有中间结果保存在本地。

所有专业工具都必须具备静态部署能力，不能因为某个功能需要 Node.js、Python 或原生程序而偷偷引入后端。

明确浏览器技术边界，对于原始 TCP 连接、原生 Linux 程序运行等无法等价实现的功能，不承诺完整支持。

这里的 CDN 仅用于分发应用代码与依赖，不等于把用户数据上传到 CDN。

一、重新评估：哪些 CTF 能力可以纯前端实现？

我专门核对了浏览器文件系统、Pyodide、FFmpeg.wasm、WebAssembly Wireshark、浏览器反汇编器等现有实现。现在已经有不少成熟技术可直接利用。

1. 无须后端，基本能完整实现的功能
第一梯队

工具类别

	

能力

	

推荐实现




编码与解码

	

Base 系列、ASCII、Unicode、Hex、URL、HTML Entity

	

TypeScript




字节操作

	

Bit Reverse、Byte Reverse、XOR、字节序、切割、置换

	

TypeScript / WASM




古典密码

	

Caesar、Vigenère、Rail Fence、各类映射

	

TypeScript




现代密码学

	

Hash、AES、RSA、ECC、HMAC、数论工具

	

Web Crypto + JS / WASM




文件查看

	

Hex Editor、字符串提取、文件头、熵分析

	

TypeScript




图片取证

	

PNG/BMP 高度、CRC、Chunk、LSB、位平面

	

Canvas + TS / WASM




二维码

	

QR 解码、结构修复、Mask、RS 纠错

	

TypeScript / WASM




压缩文件

	

ZIP、Gzip、Zlib、Deflate、Brotli 等

	

TS / WASM




文件结构

	

PNG、BMP、ZIP、ELF、PE、SQLite、PDF 解析

	

TS / WASM




数据处理

	

JSON、XML、CSV、正则、JWT、SQL

	

TypeScript / WASM




音频分析

	

Waveform、FFT、频谱、Morse、DTMF

	

Web Audio / WASM




Git 取证

	

Commit、Object、Blob、历史文件恢复

	

isomorphic-git + 自定义分析




自动分析

	

文件识别、候选解码、自动排列与验证

	

TypeScript / WASM




Workflow

	

Recipe、DAG、分支、缓存、历史、撤销

	

TypeScript

这里有一个重要区别：浏览器能实现算法，不等于所有高级攻击求解都能在合理时间内完成。

例如 RSA 小规模数学攻击可以完整实现，但大规模整数分解仍受用户计算设备性能、内存和浏览器限制。

Git 方面已有 
isomorphic-git
，能够在浏览器执行 Git 对象操作；SQLite 可使用 
sql.js
 在 WebAssembly 中本地执行。
GitHub
+1

2. 需要 WASM，但已经有现实可行的路线

功能

	

参考方案

	

可行性判断




Python 在线执行

	

Pyodide

	

高




音视频处理

	

FFmpeg.wasm

	

高，注意资源消耗




PCAP 解析

	

webShark / Wiregasm

	

高




SQLite 查询

	

sql.js

	

高




ELF / PE 反汇编

	

Capstone.js

	

高




高级二进制解析

	

Kaitai Struct JS / WASM 解析器

	

高




OCR

	

Tesseract.js

	

高




图片处理

	

OpenCV.js / 自有 WASM

	

高




软件 CPU 模拟

	

v86

	

可行但重量级




部分高级密码学

	

Rust/C/C++ → WASM

	

高




Python / JS 数据解混淆

	

自定义静态分析器 + 浏览器解释器

	

高




C/C++ 在线编译

	

WASM Clang + WASI Runtime 等组合

	

实验性，工程成本高




完整反编译 / 动态逆向

	

移植专用工具链

	

复杂，不宜首期承诺

webShark 已经提供完全在浏览器中解析 PCAP 的静态部署模式，包括通过 WASM 加载 Wireshark 协议分析引擎。它甚至提供了 GitHub Pages 构建方式，不必运行配套后端。
GitHub

Pyodide 则明确支持在浏览器 Worker 中运行 Python，并加载兼容的 Python 包；但普通 Linux/Windows 原生 Python 扩展并不能直接安装，必须有纯 Python Wheel 或专门构建的 WASM 版本。
Version 314.0.7
+1

这意味着 PCAP、Python、反汇编、视频等高级功能也不必因为坚持静态托管而放弃。

3. 纯前端存在硬性限制的能力

这里必须明确，避免开发到后期才发现做不到。

功能

	

浏览器限制

	

建议处理方式




任意 TCP/UDP 连接

	

普通网页不能直接使用原始 Socket

	

不实现通用远程 Pwn 连接器




任意网站 HTTP 请求

	

受 CORS、浏览器安全策略约束

	

只支持允许跨域的目标或离线请求文件




完整 Linux ELF 执行

	

不能直接调用宿主 OS 执行原生程序

	

仅通过 WASM 或 CPU 模拟器运行




原生 GDB / ptrace

	

浏览器不提供宿主进程调试接口

	

做模拟器调试或静态分析




完整在线 C++ 判题

	

WASM 与原生 OJ 环境不等价

	

提供 WASM 代码实验环境，不承诺判题机等价




系统级内存取证

	

无法直接读取用户计算机的进程内存

	

分析用户主动导入的内存镜像




大型暴力破解

	

受浏览器 CPU、内存、执行环境限制

	

设预算，允许终止和恢复




云端任务与跨设备同步

	

没有服务端存储

	

导入导出 Workspace




任意 DNS / WHOIS 查询

	

缺少通用原始网络接口

	

离线解析，或单独标明外部服务依赖

WebSocket 是一个特例：如果 CTF 目标本来就提供 ws:// 或 wss:// 接口，浏览器可以尝试直接连接，但不能把普通 TCP 服务自动当成 WebSocket。目标仍可以检查 Origin 并拒绝连接。
MDN

对于 OI/ACM，我会保留 Python、JS、TS 运行和数据生成、对拍的浏览器方案，但将“与正式 OJ 一致的原生 C++ 评测”列为非目标。

二、最终架构：完全没有服务器计算层

CDN Static Assets

HTML · CSS · JS · WASM · 字典 · 格式定义 · 静态资源

Browser Application

React · Workbench · Tool Search · Pipeline · Viewers

Client-Side Core

Artifact Store · Operation Registry · Analysis Engine · DAG Executor

TypeScript Workers

编码、文件操作、格式解析、自动分析

WASM Workers

Python、FFmpeg、PCAP、复杂计算、反汇编

Browser Local Storage

OPFS · IndexedDB · File / Blob · Cache Storage

用户数据与所有计算均留在浏览器

原先架构中的 Backend Runner、Remote Gateway、Job Server、Cloud Database 全部取消。

此外也不需要账号系统、用户文件上传 API、容器调度器、任务队列服务器，甚至不需要任何数据库服务。

构建时可以使用 Node.js、Rust、Clang 等开发工具；部署产物则只是静态文件。 这不违反纯前端要求。

三、本地文件系统怎么设计？

这是纯前端架构中需要优先解决的问题。

我建议采用四种浏览器能力，各自承担不同职责。

技术

	

用途

	

是否需要持久化




File / Blob

	

用户刚选择的文件、临时产物

	

不一定




IndexedDB

	

项目、Artifact 元数据、Pipeline、历史

	

是




OPFS

	

中间文件、二进制数据、持久化附件

	

是




Cache Storage

	

JS、CSS、WASM、静态资源离线缓存

	

是

OPFS 已经得到现代主流浏览器支持，既可以异步读取，也可以在 Dedicated Worker 中通过 FileSystemSyncAccessHandle 高效进行随机读写。这非常适合大型 Hex Editor。
MDN
+1

1. 不要把所有文件立即复制进 OPFS

建议区分两种模式：

临时模式（Quick Tool）

用户拖进一个 500 MB 文件，平台直接使用 File API 分块读取，不强制复制 500 MB 到浏览器存储。

关闭页面后不保证保留原文件。

工作区模式（Workspace）

用户可以选择将附件保存到本地 Workspace。系统将文件分块写入 OPFS，并把引用和处理历史写入 IndexedDB。

保存后刷新页面仍能恢复。

这两种模式必须同时支持，否则简单工具会变得过于沉重，而复杂题目又无法继续分析。

2. 建议的内部文件引用模型
type ArtifactSource =
  | {
      kind: "file";
      file: File;
    }
  | {
      kind: "opfs";
      path: string;
    }
  | {
      kind: "slice";
      parentId: string;
      offset: number;
      length: number;
    }
  | {
      kind: "memory";
      bytes: Uint8Array;
    };

其中 file 和 memory 是运行期数据源，持久化时不能仅保存这些 JavaScript 对象的普通 JSON 描述。

例如 PCAP 中提取一个 4 MB 的 TCP Payload，不必立即生成新的 4 MB 文件。它可以先引用原文件中的一段字节；如果需要跨多个位置重组，则使用一个虚拟拼接 ByteSource，必要时才物化写入 OPFS。

不过只有连续且未变换的数据才适合简单 Slice。经过解压、XOR、重排的输出，需要另行处理。

3. 持久化不能只靠 OPFS

OPFS 和 IndexedDB 都受到浏览器的存储配额、清理及隐私浏览模式限制。即使使用 navigator.storage.persist() 请求更持久的存储，也不能抵御用户主动清除网站数据。
MDN

因此必须有：

完整 Workspace 导出，例如 .ctfwork（内部采用 ZIP + Manifest）。

Workspace 导入、版本迁移和内容校验。

存储占用查看、清理无引用产物。

自动保存操作历史。

原始文件缺失时提示重新选择文件。

只导出 Recipe、不携带附件的轻量模式。

Workspace 的正式备份是可下载的文件，而不是浏览器内部数据库。

另外，建议从项目第一天就使用固定正式域名。浏览器本地存储按 Origin 隔离，后续换域名不会自动迁移原来的 Workspace。

四、Worker / WASM 执行架构

不要为每个工具都创建独立 Worker，也不要让所有 WASM 模块常驻内存。

建议将执行器分为：

Worker

	

功能




general.worker

	

普通编码、字节变换、文本处理




analysis.worker

	

自动检测、文件签名、候选搜索




storage.worker

	

OPFS 随机读写、文件流操作




python.worker

	

Pyodide Python Runtime




media.worker

	

音视频处理与 FFmpeg




pcap.worker

	

Wiregasm / 协议分析




reverse.worker

	

反汇编及静态逆向工具

这里说的是 Worker 类型，不意味着同一时间一定运行七个 Worker。

例如用户只使用 Base64，就不应该下载 Pyodide、Wiregasm、FFmpeg，也不应该启动这些引擎。

功能模块按需加载

重要

基础工具

应用启动后即可使用

图片分析

打开图片时加载

Python Runtime

首次运行 Python 时加载

Wireshark WASM

导入 PCAP 时加载

FFmpeg WASM

请求高级媒体处理时加载

概念性加载顺序示意，横条不代表实测资源大小。
需要特别处理的三个问题

第一，Worker 可以隔离 UI 卡顿，但不能被当成安全沙箱。

如果把不可信 JavaScript 直接丢进同源 Worker 执行，它仍可能访问部分浏览器 API。对于需要运行用户任意代码的功能，应使用受限制的 iframe sandbox、独立静态 Origin 或明确受限的 WASM 运行环境，并仅通过消息接口提供必要输入。MDN 也明确警告不能对同源 iframe 随意同时开启 allow-scripts 和 allow-same-origin。
MDN

尤其是分析恶意 PowerShell、Python Pickle、JavaScript 等样本，默认必须采用静态解析，不能直接运行原始恶意代码。

第二，必须支持终止任务。

每个任务应有：

Abort / Cancel。

计算时间预算。

输入输出大小限制。

最大候选数量和搜索深度。

错误返回。

在必要时终止并重新创建 Worker。

浏览器并不能保证精确的 CPU、内存配额，因此不能承诺与独立容器沙箱相同的资源隔离。

第三，尽量避免重复复制大型 ArrayBuffer。

数据传输优先使用 Transferable、Blob / File 引用、分块流；在跨源隔离可用时，才考虑 SharedArrayBuffer 等共享内存手段。

五、CDN 静态部署：需要提前确定的重要细节

这是整个方案很容易被忽略的一点。

纯静态托管，不代表可以完全不配置 HTTP Header。

部分多线程 WASM 运行时依赖 SharedArrayBuffer，需要浏览器处于 Cross-Origin Isolated 状态。

MDN 说明，典型配置需要 Cross-Origin-Opener-Policy: same-origin 和 Cross-Origin-Embedder-Policy: require-corp，同时不能被 Permissions Policy 禁止。FFmpeg.wasm 的多线程版本也明确要求 SharedArrayBuffer。
MDN
+1

1. 推荐的部署平台

方案

	

静态托管

	

自定义 Header

	

我的建议




Cloudflare Pages

	

支持

	

支持 _headers

	

首选




Netlify

	

支持

	

支持 _headers

	

同样合适




GitHub Pages

	

支持

	

HTTP Header 控制有限

	

适合基础或单线程构建




自有对象存储 + CDN

	

支持

	

取决于 CDN 配置

	

合适，但需要额外配置

Cloudflare Pages 和 Netlify 均提供在静态文件部署中配置自定义响应 Header 的机制，不需要引入计算后端。
Cloudflare Pages docs
+1

2. 静态 Header 示例

如果使用 Cloudflare Pages 或 Netlify，可以在 Vite 项目的 public/_headers 中放入：

/*
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp
  X-Content-Type-Options: nosniff

然后执行：

npm run build

最终发布 dist/ 即可。

这里还应验证：

crossOriginIsolated === true。

Worker 能正确加载。

WASM 以正确的 MIME Type 交付。

跨域资源满足 CORS / CORP 要求。

FFmpeg 多线程版本能够启动。

Service Worker 离线返回资源后仍满足要求。

对于大型 WASM 依赖，最好随项目一起构建为版本固定的静态资源，再由自己的 CDN 域名分发，不要在运行时随意从第三方 CDN 拉取最新版脚本。

3. 建议使用 PWA，提供离线模式

Service Worker 能缓存页面、JS、CSS、WASM 等应用资源，让已缓存的功能断网后继续运行。这不需要后台计算服务。
MDN

我建议设置两种资源缓存：

Core Cache：基础 UI、编码器、Hex、文本、PNG/BMP 基础工具，首次加载即缓存。

Optional Packs：Pyodide、FFmpeg、Wiregasm、OCR、逆向分析器等，用户第一次打开或主动选择离线包时下载。

但要区分“已经可以运行”与“资源全部可离线”：如果某个 Pyodide 包或 WASM 文件还没有下载，断网后它自然无法首次加载。

静态页面路由则推荐优先用 Hash Router，或者给 CDN 配好 SPA Fallback，避免用户刷新 /tools/png 这样的页面出现 404。

六、重新规划项目目录

我建议第一版控制在一个 Vite 项目中。不要因为存在很多工具就立即建立复杂 Monorepo。

ctf-workbench/
├── public/
│   ├── _headers
│   ├── manifest.webmanifest
│   └── assets/
│       ├── dictionaries/
│       └── formats/
│
├── src/
│   ├── app/
│   │   ├── routes/
│   │   ├── layout/
│   │   └── state/
│   │
│   ├── core/
│   │   ├── artifact/
│   │   ├── bytesource/
│   │   ├── operation/
│   │   ├── pipeline/
│   │   ├── analysis/
│   │   └── storage/
│   │
│   ├── workers/
│   │   ├── general.worker.ts
│   │   ├── analysis.worker.ts
│   │   └── storage.worker.ts
│   │
│   ├── operations/
│   │   ├── encoding/
│   │   ├── binary/
│   │   ├── crypto/
│   │   ├── image/
│   │   ├── forensics/
│   │   └── reverse/
│   │
│   ├── formats/
│   │   ├── png/
│   │   ├── bmp/
│   │   ├── zip/
│   │   └── pcap/
│   │
│   ├── viewers/
│   │   ├── hex/
│   │   ├── image/
│   │   ├── structure/
│   │   └── timeline/
│   │
│   ├── runtimes/
│   │   ├── pyodide/
│   │   ├── ffmpeg/
│   │   └── wiregasm/
│   │
│   └── components/
│
├── tests/
│   ├── vectors/
│   ├── fixtures/
│   └── integration/
│
├── index.html
├── vite.config.ts
└── package.json

这套结构只包含前端资源和编译阶段所需的代码，完全不需要服务器文件夹。

第三方工具 SDK 和 WASM 模块也可以在 runtimes/ 下拥有独立的适配器，但要保持和内置 Operation 一样的接口。

七、先做哪些功能最合理？

全前端反而更适合以真实数据处理流程为中心来开发。

阶段

	

开发内容

	

必须验收的能力




M0

	

Vite、静态托管、Worker、WASM 加载、文件导入

	

dist/ 可以直接 CDN 部署




M1

	

ByteSource、Artifact、Hex、Base、XOR、位操作

	

大文件分块、数据无损




M2

	

PNG/BMP、LSB、位平面、文件结构与修复

	

能复现实际图片隐写流程




M3

	

Workspace、OPFS、历史、Recipe

	

刷新恢复，完整导入导出




M4

	

Detector、Finding、候选搜索、DAG

	

自动分析有证据、有预算




M5

	

Pyodide、SQLite、PCAP、Git、OCR 等

	

按需加载且无后端依赖




M6

	

Reverse、Audio、Advanced Crypto、OI 工具

	

WASM 能力逐项验证

M0 最关键的验收是：

将 dist/ 部署到一个空的静态站点，禁用所有自建 API，确认核心功能可以完整工作。

同时需要针对现代 Chromium、Firefox、Safari 进行兼容性测试。可以先以桌面 Chromium/Edge 为完整功能基线，对其他浏览器做能力检测和降级，不必一开始要求所有复杂 WASM 引擎跨浏览器行为完全一致。

我想额外强调两个实际 CTF 陷阱

1. 图片隐写不能只依赖 Canvas。

Canvas 解码图片时可能对颜色值、Alpha、色彩空间等进行转换，尤其透明像素 RGB、16-bit PNG 原始通道和某些调色板隐写，不能保证解码后的 Canvas 数据仍保留原始信息。

所以应该同时存在：

原始文件结构 / 像素样本解析器，用于准确隐写分析。

Canvas / WebGL / WebGPU 视图，用于显示和可视化。

2. PCAP 分析应当区分轻量读取和完整协议解析。

Wiregasm 这类 WASM 引擎很强，但完整 PCAP 装入 WASM 内存可能开销较大。前期可以用 TS 实现文件头、Packet Record、简单 Payload Extract，深度分析时再加载专业引擎。

这和之前提出的 Cheap Scan → Deep Scan 非常契合。

八、我建议增加一项新的首要验收指标

之前的方案强调正确性、性能、可扩展性，现在应该把无后端依赖与隐私提升为第一等级要求。

指标

	

验收要求




静态部署

	

只需要 HTML/JS/CSS/WASM/静态资源




无服务端计算

	

所有处理发生在客户端




数据不上传

	

用户附件、文本、密钥无隐式外发




网络可观察

	

不向未声明的远程接口发送计算数据




无账号

	

无登录、无用户数据库




离线能力

	

已缓存的核心工具可以断网使用




数据持久化

	

用户主动保存的工作区可恢复




可迁移

	

Workspace / Recipe 可导出




低内存

	

大文件按需读取、避免整体复制




可扩展

	

新 Operation 不必修改通用 UI




有界计算

	

耗时任务可取消，候选数量受限




安全隔离

	

不可信代码不在应用主执行上下文运行

可以加一个自动化测试：在浏览器中导入测试附件，完成完整 Recipe，同时记录所有网络请求，确认没有把用户数据提交给远程服务。

另外，对浏览器存储、代码执行、跨源 iframe 和 WASM 加载分别建立安全测试，不能只通过“页面能运行”判断系统符合隐私目标。

最终建议

我现在更倾向于这套非常明确的技术方案：

CTF Workbench · Browser-Only
Web 框架	React + TypeScript + Vite
运行引擎	Web Workers + WebAssembly
本地数据	File/Blob + OPFS + IndexedDB
工作流	Typed Operation + DAG
重型工具	按需加载的 WASM Runtime
离线能力	PWA + Service Worker
部署	Cloudflare Pages 静态资源
计算后端	

无


用户账号和服务端数据库	

无

我还建议把系统未来的核心开发原则定为：

优先 TypeScript → 性能不足再使用 WASM → 专业工具能移植则集成 → 浏览器确实无法实现的能力明确标注限制，不为它引入后端。

这并不意味着放弃你原本想要的几百种 CTF/OI 工具。实际上，Base64、Hex、位操作、PNG 修复、USB-HID、PCAP、Python、SQLite、静态反汇编、自动候选搜索等都可以按照这个目标继续推进。

最合理的下一份开发设计应该是 Browser-Only Core Specification v1：把 ByteSource、Artifact Store、Operation SDK、Worker Runtime、Browser Persistence 的接口和生命周期固定下来，然后用 PNG 高度修复 → LSB 提取 → 解码这条真实 CTF 工作流验证它。

这条链路跑通后，再扩展其他几百个工具，基本不需要推翻架构。
