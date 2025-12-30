# ida.py - IDA Pro 自动分析脚本
#
# 用法:
#   反汇编模式 (disasm):
#     ida64.exe -A -S"ida.py --mode disasm --func FuncName" "path/to/pe.exe"
#
#   符号重映射模式 (symbol_remap):
#     ida64.exe -A -S"ida.py --mode symbol_remap --symbol_remap_file path/to/SymbolMapping.yaml" "path/to/pe.exe"
#     ida64.exe -A -S"ida.py --mode symbol_remap" "path/to/pe.exe"  # 使用 PE 同目录下的 SymbolMapping.yaml
#
# ============================================================================
# IDA 自动加载配置 (ida.cfg 或命令行参数)
# ============================================================================
# 为了让 IDA 自动以全默认方式加载 PE64 文件并自动加载 PDB，需要:
#
# 方法1: 使用命令行参数 (推荐用于 headless 模式)
#   ida64.exe -A -S"path\to\ida.py ..." "path\to\pe.exe"
#   -A: 自主模式，自动回答所有对话框
#
# 方法2: 在 %IDAUSR%\ida.cfg 或 %IDADIR%\cfg\ida.cfg 中添加:
#   OPENIDB_ONLYNEW = YES           ; 自动选择新数据库
#   ABANDON_DATABASE = YES          ; 放弃旧数据库
#   PDB_AUTOLOAD = YES              ; 自动加载 PDB
#   PDB_PROVIDER = "MSDIA140"       ; 使用 Microsoft DIA SDK
#   PDB_DOWNLOAD = YES              ; 自动从符号服务器下载 PDB
#   PE_LOAD_ANSWER = 1              ; 自动选择 PE 加载器 (1=PE64)
#
# 方法3: 环境变量
#   set TVHEADLESS=1                ; 完全无头模式
#
# 完整命令示例 (headless + 自动应答):
#   ida64.exe -A -P -S"D:\kphtools\ida\ida.py --mode disasm --func PsSetCreateProcessNotifyRoutine" "D:\kphtools\symbols\amd64\ntoskrnl.exe.10.0.22621.3668\ntoskrnl.exe"
# 完整命令示例 (GUI模式):
#   ida64.exe -P -S"D:\kphtools\ida\ida.py --mode disasm --func PsSetCreateProcessNotifyRoutine" "D:\kphtools\symbols\amd64\ntoskrnl.exe.10.0.22621.3668\ntoskrnl.exe"
#

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
import ida_idaapi
import ida_segment
import idautils
import idc
import os
import sys
import yaml

# 需要输出反汇编的函数名
DISASM_FUNCTION = ""

# 进行 Symbol Mapping 映射的 yaml文件
# 例如:
# sub_140822108: PspSetCreateProcessNotifyRoutine
SYMBOL_MAPPING_FILE = "SymbolMapping.yaml"

def parse_script_args():
    """
    解析 IDA 脚本参数
    IDA 通过 idc.ARGV 传递 -S 后的参数
    示例: -S"script.py --mode disasm --func FuncName"
    示例: -S"script.py --mode symbol_remap --symbol_remap_file path/to/mapping.yaml"
    """
    args = {
        "mode": "disasm",
        "func": DISASM_FUNCTION,
        "output": None,  # 自动生成
        "symbol_remap_file": SYMBOL_MAPPING_FILE,  # symbol_remap 模式使用的映射文件
    }

    argv = idc.ARGV if hasattr(idc, 'ARGV') else []

    i = 1  # 跳过脚本名
    while i < len(argv):
        if argv[i] == "--mode" and i + 1 < len(argv):
            args["mode"] = argv[i + 1]
            i += 2
        elif argv[i] == "--func" and i + 1 < len(argv):
            args["func"] = argv[i + 1]
            i += 2
        elif argv[i] == "--output" and i + 1 < len(argv):
            args["output"] = argv[i + 1]
            i += 2
        elif argv[i] == "--symbol_remap_file" and i + 1 < len(argv):
            args["symbol_remap_file"] = argv[i + 1]
            i += 2
        else:
            i += 1

    return args

def wait_auto():
    """等待 IDA 自动分析完成"""
    print("[*] Waiting for auto-analysis to complete...")
    ida_auto.auto_wait()
    print("[*] Auto-analysis completed.")

def load_symbol_mapping(mapping_path):
    """
    加载 SymbolMapping.yaml 文件

    Args:
        mapping_path: SymbolMapping.yaml 文件路径

    Returns:
        符号映射字典，格式为 {unmapped_name: mapped_name}
        例如: {"sub_140822108": "PspSetCreateProcessNotifyRoutine"}
    """
    if not os.path.exists(mapping_path):
        print(f"[!] Symbol mapping file not found: {mapping_path}")
        return {}

    try:
        with open(mapping_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not data:
                return {}
            # 直接返回原始格式: {unmapped: mapped}
            # 例如: sub_140822108: PspSetCreateProcessNotifyRoutine
            return data
    except Exception as e:
        print(f"[!] Failed to load SymbolMapping.yaml: {e}")
        return {}


def get_function_address(func_name):
    """
    通过函数名获取函数起始地址

    Args:
        func_name: 函数名称

    Returns:
        函数起始地址，找不到返回 ida_idaapi.BADADDR
    """
    # 方法1: 使用 ida_name.get_name_ea
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
    if ea != ida_idaapi.BADADDR:
        return ea

    # 方法2: 遍历所有函数名查找
    for func_ea in idautils.Functions():
        name = ida_funcs.get_func_name(func_ea)
        if name == func_name:
            return func_ea

    return ida_idaapi.BADADDR


def rename_function(ea, new_name):
    """
    重命名函数

    Args:
        ea: 函数地址
        new_name: 新的函数名

    Returns:
        成功返回 True，失败返回 False
    """
    try:
        # 使用 ida_name.set_name 重命名
        # SN_CHECK: 检查名称是否有效
        # SN_NOWARN: 不显示警告
        result = ida_name.set_name(ea, new_name, ida_name.SN_CHECK | ida_name.SN_NOWARN)
        return result
    except Exception as e:
        print(f"[!] Failed to rename function at {hex(ea)} to {new_name}: {e}")
        return False


def get_image_base():
    """
    获取当前加载的 PE 文件的 ImageBase

    Returns:
        ImageBase 地址
    """
    # 使用 ida_nalt 获取 ImageBase
    import ida_nalt
    return ida_nalt.get_imagebase()


def apply_symbol_remap(mapping_path):
    """
    应用符号映射，将所有 unmapped 名称重命名为真实名称
    同时在 YAML 文件中添加 ImageBase 信息

    Args:
        mapping_path: SymbolMapping.yaml 文件路径

    Returns:
        (success_count, fail_count, skip_count) 元组
    """
    # 加载映射
    mappings = load_symbol_mapping(mapping_path)
    if not mappings:
        print("[!] No symbol mappings to apply")
        return 0, 0, 0

    print(f"[*] Loaded {len(mappings)} symbol mappings from: {mapping_path}")

    # 获取 ImageBase 并检查是否需要添加
    image_base = get_image_base()
    image_base_key = f"{image_base:X}"  # 转换为十六进制字符串，如 "140000000"

    # 检查是否已存在 ImageBase 条目
    if image_base_key not in mappings:
        # 添加 ImageBase 条目到映射中
        mappings[image_base_key] = "ImageBase"
        print(f"[*] Adding ImageBase entry: {image_base_key}: ImageBase")

        # 更新 YAML 文件
        try:
            with open(mapping_path, "w", encoding="utf-8") as f:
                yaml.dump(mappings, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(f"[+] Updated {mapping_path} with ImageBase")
        except Exception as e:
            print(f"[!] Failed to update YAML file with ImageBase: {e}")
    else:
        print(f"[*] ImageBase entry already exists: {image_base_key}")

    success_count = 0
    fail_count = 0
    skip_count = 0

    for unmapped_name, mapped_name in mappings.items():
        # 查找 unmapped 名称对应的地址
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, unmapped_name)
        if ea == ida_idaapi.BADADDR:
            print(f"  [-] Symbol not found: {unmapped_name}")
            skip_count += 1
            continue

        # 重命名
        if rename_function(ea, mapped_name):
            print(f"  [+] Renamed: {unmapped_name} -> {mapped_name} at {hex(ea)}")
            success_count += 1
        else:
            print(f"  [!] Failed to rename: {unmapped_name} -> {mapped_name}")
            fail_count += 1

    return success_count, fail_count, skip_count


def get_section_name(ea):
    """
    获取地址所在的段名称

    Args:
        ea: 地址

    Returns:
        段名称字符串，如 ".text"
    """
    seg = ida_segment.getseg(ea)
    if seg:
        return ida_segment.get_segm_name(seg)
    return ""


def format_address(ea):
    """
    格式化地址为 SECTION:OFFSET 格式

    Args:
        ea: 地址

    Returns:
        格式化的地址字符串，如 ".text:0000000140822108"
    """
    section = get_section_name(ea)
    if section:
        return f"{section}:{ea:016X}"
    return f"{ea:016X}"


def get_function_disassembly(func_ea):
    """
    获取函数的反汇编代码

    Args:
        func_ea: 函数起始地址

    Returns:
        反汇编代码字符串
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None

    lines = []

    # 获取函数名
    func_name = ida_funcs.get_func_name(func_ea)

    # 检查是否为导出函数并添加注释
    ordinal = get_export_ordinal(func_ea)
    if ordinal is not None:
        lines.append(f"; Exported entry {ordinal}. {func_name}")
        lines.append("")

    # 获取函数类型签名
    func_type = idc.get_type(func_ea)
    if func_type:
        lines.append("; " + func_type)

    # 添加 public 声明和函数头
    lines.append(f"{format_address(func_ea)}                 public {func_name}")
    lines.append(f"{format_address(func_ea)} {func_name}     proc near")

    # 遍历函数内的每条指令
    ea = func.start_ea
    while ea < func.end_ea:
        line_parts = []

        # 添加地址
        addr_str = format_address(ea)
        line_parts.append(addr_str)

        # 检查是否有标签（跳转目标等）
        name_at_ea = ida_name.get_name(ea)
        if name_at_ea and name_at_ea != func_name:
            # 这是一个标签行
            lines.append(f"{addr_str}")
            lines.append(f"{addr_str} {name_at_ea}:")

        # 生成反汇编行并移除颜色标签
        disasm_line = idc.generate_disasm_line(ea, 0)
        if disasm_line:
            clean_line = ida_lines.tag_remove(disasm_line)
            lines.append(f"{addr_str}                 {clean_line}")

        # 移动到下一条指令
        ea = idc.next_head(ea, func.end_ea)
        if ea == ida_idaapi.BADADDR:
            break

    # 添加函数结束标记
    lines.append(f"{format_address(func.end_ea - 1)} {func_name}     endp")

    return "\n".join(lines)


def get_export_ordinal(ea):
    """
    获取函数的导出序号

    Args:
        ea: 函数地址

    Returns:
        导出序号，未导出返回 None
    """
    try:
        import ida_entry
        # 遍历所有导出项查找匹配地址
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            entry_ea = ida_entry.get_entry(ordinal)
            if entry_ea == ea:
                return ordinal
        return None
    except:
        return None

def get_function_pseudocode(func_ea):
    """
    获取函数的伪代码 (需要 Hex-Rays 反编译器)

    Args:
        func_ea: 函数起始地址

    Returns:
        伪代码字符串，失败返回 None
    """
    try:
        # 初始化 Hex-Rays 反编译器
        if not ida_hexrays.init_hexrays_plugin():
            print("[!] Hex-Rays decompiler is not available")
            return None

        # 反编译函数
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            print(f"[!] Failed to decompile function at {hex(func_ea)}")
            return None

        # 获取伪代码行
        pseudocode = cfunc.get_pseudocode()
        lines = []
        for line in pseudocode:
            # 移除颜色标签
            clean_line = ida_lines.tag_remove(line.line)
            lines.append(clean_line)

        return "\n".join(lines)

    except Exception as e:
        print(f"[!] Decompilation error: {e}")
        return None

def build_output_path(input_file, func_name):
    """
    根据输入文件路径和函数名生成输出文件路径

    Args:
        input_file: 输入的 PE 文件路径
        func_name: 函数名称

    Returns:
        输出 YAML 文件路径 (函数名.yaml)
    """
    # 获取输入文件所在目录
    input_dir = os.path.dirname(input_file)
    # 使用函数名作为文件名
    return os.path.join(input_dir, f"{func_name}.yaml")

def export_function_info(func_name, func_ea, disasm_code, output_path, pseudocode=None):
    """
    导出函数信息到 YAML 文件

    Args:
        func_name: 函数名称
        func_ea: 函数地址
        disasm_code: 反汇编代码
        output_path: 输出文件路径
        pseudocode: F5 伪代码 (可选)
    """
    # 确保输出目录存在
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 构建数据结构
    data = {
        "virtualaddress": hex(func_ea),
        "disasm_code": disasm_code
    }

    # 如果有伪代码则添加 procedure 字段
    if pseudocode:
        data["procedure"] = pseudocode

    # 自定义 Dumper 使多行字符串使用 literal block 格式 (|)
    class LiteralDumper(yaml.SafeDumper):
        pass

    def literal_str_representer(dumper, data):
        if '\n' in data:
            # 多行字符串使用 literal block style
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)

    LiteralDumper.add_representer(str, literal_str_representer)

    with open(output_path, "w", encoding="utf-8") as fp:
        yaml.dump(data, fp, Dumper=LiteralDumper, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"[+] Exported to: {output_path}")

def main():
    """主函数"""
    # 解析参数
    args = parse_script_args()
    mode = args["mode"]

    print(f"[*] Mode: {mode}")

    # 等待自动分析完成
    wait_auto()

    # 获取当前数据库对应的输入文件路径
    input_file = idc.get_input_file_path()
    print(f"[*] Input file: {input_file}")

    # 根据模式执行不同的操作
    if mode == "symbol_remap":
        # 符号重映射模式
        if args["symbol_remap_file"]:
            mapping_path = args["symbol_remap_file"]
        else:
            # 默认使用 PE 同目录下的 SymbolMapping.yaml
            mapping_path = os.path.join(os.path.dirname(input_file), "SymbolMapping.yaml")

        print(f"[*] Symbol mapping file: {mapping_path}")

        # 应用符号映射
        success, fail, skip = apply_symbol_remap(mapping_path)
        print(f"\n[+] Symbol remap completed:")
        print(f"    Success: {success}")
        print(f"    Failed:  {fail}")
        print(f"    Skipped: {skip}")

        # headless 模式下退出
        idc.qexit(0 if fail == 0 else 1)
        return

    elif mode == "disasm":
        # 反汇编模式
        func_name = args["func"]
        if not func_name:
            print("[!] Function name is required for disasm mode")
            print("    Usage: --mode disasm --func FuncName")
            idc.qexit(1)
            return

        print(f"[*] Target function: {func_name}")

        # 确定输出路径
        if args["output"]:
            output_path = args["output"]
        else:
            output_path = build_output_path(input_file, func_name)

        # 查找函数地址
        func_ea = get_function_address(func_name)
        if func_ea == ida_idaapi.BADADDR:
            print(f"[!] Function '{func_name}' not found")
            idc.qexit(1)
            return

        print(f"[+] Found function '{func_name}' at {hex(func_ea)}")

        # 跳转到函数 (在 GUI 模式下有效)
        ida_kernwin.jumpto(func_ea)

        # 获取反汇编代码
        disasm_code = get_function_disassembly(func_ea)
        if not disasm_code:
            print(f"[!] Failed to get disassembly for '{func_name}'")
            idc.qexit(1)
            return

        print(f"[+] Got disassembly for '{func_name}'")

        # 获取 F5 伪代码
        pseudocode = get_function_pseudocode(func_ea)
        if pseudocode:
            print(f"[+] Got pseudocode for '{func_name}'")
        else:
            print(f"[*] No pseudocode available for '{func_name}' (Hex-Rays may not be available)")

        # 导出结果
        export_function_info(func_name, func_ea, disasm_code, output_path, pseudocode)

        # headless 模式下退出
        idc.qexit(0)

    else:
        print(f"[!] Unknown mode: {mode}")
        print("    Supported modes: disasm, symbol_remap")
        idc.qexit(1)

if __name__ == "__main__":
    main()
