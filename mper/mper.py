"""
mper.py - Discord Bot Permission Scanner

Scans Python code to detect required Discord permissions and generates
bot invite links with the appropriate permission bits.

Detection methods (in order of priority):

1. Method-based detection (PRIMARY - for invite link):
   - Detects discord.py method calls and infers required BOT permissions
   - e.g., member.ban() -> ban_members, channel.purge() -> manage_messages
   - Tracks call sites (file, line, method) as evidence
   - Uses receiver type hints for better accuracy (member.ban vs guild.ban)

2. @bot_has_permissions decorator (SUPPLEMENTARY):
   - Explicit bot permission declarations by the developer
   - Added to invite link permissions

3. @has_permissions decorator (USER REQUIREMENTS ONLY):
   - These are USER permission requirements, NOT bot permissions
   - NOT included in invite link (user permissions != bot permissions)
   - Shown in report for reference only

The invite link is generated from:
- Method-based inferred permissions (what the bot actually does)
- @bot_has_permissions declarations (explicit bot requirements)
"""

import argparse
import ast
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .permissions import (
    APP_COMMAND_BOT_PERMISSION_DECORATORS,
    APP_COMMAND_PERMISSION_DECORATORS,
    BOT_PERMISSION_DECORATORS,
    MEMBER_EDIT_KWARGS_PERMISSIONS,
    PERMISSION_DECORATORS,
    WRAPPER_DECORATORS,
    calculate_permission_integer,
    get_permission_value,
    get_permissions_from_method,
    infer_receiver_type,
    resolve_permission_name,
)


@dataclass
class MethodCall:
    """Represents a detected method call that requires permissions."""
    method_name: str
    receiver_hint: Optional[str]
    line_number: int
    permissions: List[str]
    confidence: str
    description: str
    kwargs: List[str] = field(default_factory=list)

    @property
    def call_chain(self) -> str:
        """Get the full call chain (e.g., 'member.ban')."""
        if self.receiver_hint:
            return f"{self.receiver_hint}.{self.method_name}"
        return self.method_name

# Directories to exclude by default
DEFAULT_EXCLUDE_DIRS = {
    '.venv',
    'venv',
    '.env',
    'env',
    '__pycache__',
    '.git',
    '.hg',
    '.svn',
    'node_modules',
    'site-packages',
    'dist-packages',
    '.tox',
    '.nox',
    '.pytest_cache',
    '.mypy_cache',
    'build',
    'dist',
    'egg-info',
}


class PermissionVisitor(ast.NodeVisitor):
    """AST visitor to extract permission requirements from Python code.

    PRIMARY detection: Method calls (what the bot actually does)
    SUPPLEMENTARY: @bot_has_permissions decorators (explicit declarations)
    REFERENCE ONLY: @has_permissions decorators (user requirements, not for invite)
    """

    def __init__(self, file_path: str = ""):
        self.file_path = file_path

        # PRIMARY: Method-based detection (for invite link)
        self.method_calls: List[MethodCall] = []

        # SUPPLEMENTARY: @bot_has_permissions (for invite link)
        self.bot_permissions: Set[str] = set()

        # REFERENCE ONLY: @has_permissions (NOT for invite link)
        self.user_permissions: Set[str] = set()

        self.warnings: List[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions to check for permission decorators."""
        self._check_decorators(node.decorator_list)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definitions to check for permission decorators."""
        self._check_decorators(node.decorator_list)
        self.generic_visit(node)

    def _check_decorators(self, decorators: List[ast.expr]) -> None:
        """Check decorators for permission declarations."""
        for decorator in decorators:
            self._extract_permissions_from_decorator(decorator)

    def _extract_permissions_from_decorator(self, decorator: ast.expr, is_bot: bool = False) -> None:
        """Extract permission names from a decorator, recursively handling nested decorators."""
        if isinstance(decorator, ast.Call):
            decorator_name = self._get_decorator_name(decorator.func)

            # Check for wrapper decorators that may contain nested permission checks
            if decorator_name in WRAPPER_DECORATORS:
                for arg in decorator.args:
                    self._extract_permissions_from_decorator(arg, is_bot)
                for keyword in decorator.keywords:
                    if keyword.value:
                        self._extract_permissions_from_decorator(keyword.value, is_bot)
                return

            # Determine if this is a bot or user permission decorator
            is_bot_decorator = (
                decorator_name in BOT_PERMISSION_DECORATORS or
                decorator_name in APP_COMMAND_BOT_PERMISSION_DECORATORS
            )
            is_user_decorator = (
                decorator_name in PERMISSION_DECORATORS or
                decorator_name in APP_COMMAND_PERMISSION_DECORATORS or
                decorator_name == 'default_permissions'
            )

            if is_bot_decorator or is_user_decorator:
                for keyword in decorator.keywords:
                    if keyword.arg is not None:
                        perm_name = keyword.arg.lower()
                        if self._is_truthy_value(keyword.value):
                            if is_bot_decorator:
                                self._add_permission(perm_name, self.bot_permissions)
                            else:
                                self._add_permission(perm_name, self.user_permissions)

    def _is_truthy_value(self, node: ast.expr) -> bool:
        """Check if an AST node represents a truthy value."""
        if isinstance(node, ast.Constant):
            return bool(node.value)
        elif isinstance(node, ast.NameConstant):  # Python 3.7 compat
            return bool(node.value)
        elif isinstance(node, ast.Name):
            return True
        return True

    def _get_decorator_name(self, node: ast.expr) -> str:
        """Get the name of a decorator from its AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""

    def _add_permission(self, perm_name: str, target_set: Set[str]) -> None:
        """Add a permission to the target set, resolving aliases if needed."""
        resolved = resolve_permission_name(perm_name)
        if resolved:
            target_set.add(resolved)
        else:
            self.warnings.append(f"Unknown permission: {perm_name}")

    def _get_receiver_hint(self, node: ast.expr) -> Optional[str]:
        """Try to infer the receiver type from an AST node."""
        if isinstance(node, ast.Name):
            return infer_receiver_type(node.id)
        elif isinstance(node, ast.Attribute):
            # Check the attribute name (e.g., ctx.author -> "author" -> "member")
            hint = infer_receiver_type(node.attr)
            if hint:
                return hint
            # Recursively check the value
            return self._get_receiver_hint(node.value)
        elif isinstance(node, ast.Call):
            # Check for patterns like guild.get_member(...).ban()
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                # Common patterns that return specific types
                if func_name in ['get_member', 'fetch_member']:
                    return 'member'
                elif func_name in ['get_channel', 'fetch_channel']:
                    return 'channel'
                elif func_name in ['get_role']:
                    return 'role'
        return None

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to detect discord.py method usage."""
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            receiver_hint = self._get_receiver_hint(node.func.value)

            # Get kwargs for special handling (e.g., member.edit)
            kwargs = [kw.arg for kw in node.keywords if kw.arg]

            # Special handling for member.edit() with kwargs
            if method_name == 'edit' and receiver_hint == 'member' and kwargs:
                for kwarg in kwargs:
                    if kwarg in MEMBER_EDIT_KWARGS_PERMISSIONS:
                        perm, desc = MEMBER_EDIT_KWARGS_PERMISSIONS[kwarg]
                        self.method_calls.append(MethodCall(
                            method_name=f"edit:{kwarg}",
                            receiver_hint=receiver_hint,
                            line_number=node.lineno,
                            permissions=[perm],
                            confidence="high",
                            description=desc,
                            kwargs=[kwarg],
                        ))
            else:
                # Standard method lookup
                perms, confidence, desc = get_permissions_from_method(method_name, receiver_hint)
                if perms:
                    self.method_calls.append(MethodCall(
                        method_name=method_name,
                        receiver_hint=receiver_hint,
                        line_number=node.lineno,
                        permissions=perms,
                        confidence=confidence,
                        description=desc,
                        kwargs=kwargs,
                    ))

        self.generic_visit(node)

    @property
    def inferred_permissions(self) -> Set[str]:
        """All permissions inferred from method calls (PRIMARY for invite link)."""
        perms = set()
        for call in self.method_calls:
            perms.update(call.permissions)
        return perms

    @property
    def high_confidence_permissions(self) -> Set[str]:
        """Only high-confidence permissions from method calls."""
        perms = set()
        for call in self.method_calls:
            if call.confidence == "high":
                perms.update(call.permissions)
        return perms

    @property
    def invite_link_permissions(self) -> Set[str]:
        """Permissions for the invite link (method-based + @bot_has_permissions)."""
        return self.inferred_permissions | self.bot_permissions

    def get_permission_evidence(self) -> Dict[str, List[MethodCall]]:
        """Get evidence for each permission (which method calls require it)."""
        evidence: Dict[str, List[MethodCall]] = {}
        for call in self.method_calls:
            for perm in call.permissions:
                if perm not in evidence:
                    evidence[perm] = []
                evidence[perm].append(call)
        return evidence


def scan_file(file_path: str) -> Dict[str, Any]:
    """
    Scan a single Python file for permission requirements.

    Returns:
        Dictionary containing:
        - method_calls: List of MethodCall objects (PRIMARY - for invite link)
        - inferred_permissions: Set of permissions from method calls (PRIMARY)
        - bot_permissions: Set from @bot_has_permissions (SUPPLEMENTARY)
        - user_permissions: Set from @has_permissions (REFERENCE ONLY)
        - invite_link_permissions: Combined permissions for invite link
        - evidence: Dict mapping permission -> list of method calls
        - warnings: List of warning messages
    """
    empty_result = {
        'method_calls': [],
        'inferred_permissions': set(),
        'bot_permissions': set(),
        'user_permissions': set(),
        'invite_link_permissions': set(),
        'evidence': {},
        'warnings': [],
    }

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()
    except (IOError, OSError) as e:
        empty_result['warnings'] = [f"Could not read file {file_path}: {e}"]
        return empty_result
    except UnicodeDecodeError as e:
        empty_result['warnings'] = [f"Encoding error in {file_path}: {e}"]
        return empty_result

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        empty_result['warnings'] = [f"Syntax error in {file_path}: {e}"]
        return empty_result

    visitor = PermissionVisitor(file_path)
    visitor.visit(tree)

    return {
        'method_calls': visitor.method_calls,
        'inferred_permissions': visitor.inferred_permissions,
        'bot_permissions': visitor.bot_permissions,
        'user_permissions': visitor.user_permissions,
        'invite_link_permissions': visitor.invite_link_permissions,
        'evidence': visitor.get_permission_evidence(),
        'warnings': visitor.warnings,
    }


def scan_directory(
    directory: str,
    exclude_dirs: Set[str] = None,
    include_inferred: bool = True,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Scan a directory for Discord permission requirements.

    Args:
        directory: Path to the directory to scan
        exclude_dirs: Set of directory names to exclude
        include_inferred: Whether to include inferred permissions (always True for method-based)
        verbose: Whether to print detailed output

    Returns:
        Dictionary containing:
        - method_calls: List of all MethodCall objects with file paths
        - inferred_permissions: Set of permissions from method calls (PRIMARY)
        - bot_permissions: Set from @bot_has_permissions (SUPPLEMENTARY)
        - user_permissions: Set from @has_permissions (REFERENCE ONLY)
        - invite_link_permissions: Combined permissions for invite link
        - evidence: Dict mapping permission -> list of (file, method_call) tuples
        - warnings: List of warning messages
        - files_scanned: Number of files scanned
        - files_with_errors: Number of files with errors
    """
    if exclude_dirs is None:
        exclude_dirs = DEFAULT_EXCLUDE_DIRS

    all_method_calls: List[Tuple[str, MethodCall]] = []  # (file_path, method_call)
    user_permissions: Set[str] = set()
    bot_permissions: Set[str] = set()
    inferred_permissions: Set[str] = set()
    all_warnings: List[str] = []
    files_scanned = 0
    files_with_errors = 0

    for root, dirs, files in os.walk(directory):
        # Filter out excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                files_scanned += 1

                if verbose:
                    print(f"Scanning: {file_path}")

                result = scan_file(file_path)

                # Collect method calls with file path
                for call in result['method_calls']:
                    all_method_calls.append((file_path, call))

                user_permissions.update(result['user_permissions'])
                bot_permissions.update(result['bot_permissions'])
                inferred_permissions.update(result['inferred_permissions'])

                if result['warnings']:
                    files_with_errors += 1
                    all_warnings.extend(result['warnings'])

    # Build evidence dictionary: permission -> list of (file, method_call)
    evidence: Dict[str, List[Tuple[str, MethodCall]]] = {}
    for file_path, call in all_method_calls:
        for perm in call.permissions:
            if perm not in evidence:
                evidence[perm] = []
            evidence[perm].append((file_path, call))

    # Calculate invite link permissions
    # PRIMARY: method-based inferred permissions
    # SUPPLEMENTARY: @bot_has_permissions declarations
    invite_link_permissions = inferred_permissions | bot_permissions

    return {
        'method_calls': all_method_calls,
        'inferred_permissions': inferred_permissions,
        'bot_permissions': bot_permissions,
        'user_permissions': user_permissions,
        'invite_link_permissions': invite_link_permissions,
        'evidence': evidence,
        'warnings': all_warnings,
        'files_scanned': files_scanned,
        'files_with_errors': files_with_errors,
    }


def scan_directory_with_progress(
    directory: str,
    exclude_dirs: Set[str],
    include_inferred: bool,
    progress,
    task_id,
    python_files: List[str]
) -> Dict[str, Any]:
    """
    Scan a directory with progress bar support.

    This is a variant of scan_directory that updates a Rich progress bar.
    """
    all_method_calls: List[Tuple[str, MethodCall]] = []
    user_permissions: Set[str] = set()
    bot_permissions: Set[str] = set()
    inferred_permissions: Set[str] = set()
    all_warnings: List[str] = []
    files_scanned = 0
    files_with_errors = 0

    for file_path in python_files:
        files_scanned += 1

        # Update progress bar
        rel_path = os.path.basename(file_path)
        progress.update(task_id, advance=1, current_file=rel_path)

        result = scan_file(file_path)

        # Collect method calls with file path
        for call in result['method_calls']:
            all_method_calls.append((file_path, call))

        user_permissions.update(result['user_permissions'])
        bot_permissions.update(result['bot_permissions'])
        inferred_permissions.update(result['inferred_permissions'])

        if result['warnings']:
            files_with_errors += 1
            all_warnings.extend(result['warnings'])

    # Build evidence dictionary
    evidence: Dict[str, List[Tuple[str, MethodCall]]] = {}
    for file_path, call in all_method_calls:
        for perm in call.permissions:
            if perm not in evidence:
                evidence[perm] = []
            evidence[perm].append((file_path, call))

    # Calculate invite link permissions
    invite_link_permissions = inferred_permissions | bot_permissions

    return {
        'method_calls': all_method_calls,
        'inferred_permissions': inferred_permissions,
        'bot_permissions': bot_permissions,
        'user_permissions': user_permissions,
        'invite_link_permissions': invite_link_permissions,
        'evidence': evidence,
        'warnings': all_warnings,
        'files_scanned': files_scanned,
        'files_with_errors': files_with_errors,
    }


def calculate_permissions(permission_names: Set[str]) -> int:
    """Calculate the combined permission integer from permission names."""
    return calculate_permission_integer(permission_names)


def create_invite_link(
    client_id: str,
    permissions: int,
    scopes: List[str] = None
) -> str:
    """
    Discord用のOAuth2招待URLを生成する。
    
    Parameters:
    	client_id (str): ボットのクライアントID
    	permissions (int): 招待に含める権限ビットの合計値
    	scopes (List[str], optional): OAuth2スコープの一覧。省略した場合は `['bot', 'applications.commands']` を使用する
    
    Returns:
    	invite_url (str): 生成された招待URL文字列
    """
    if scopes is None:
        scopes = ['bot', 'applications.commands']

    scope_str = '%20'.join(scopes)
    return f"https://discord.com/oauth2/authorize?client_id={client_id}&permissions={permissions}&scope={scope_str}"


def generate_invite_url(
    path: str,
    client_id: str,
    scopes: List[str] = None
) -> str:
    """
    ディレクトリまたはファイルをスキャンして、必要なパーミッションを自動検出し招待URLを生成する。

    CLIと同じ動作をライブラリから簡単に実行できる。

    Args:
        path: スキャン対象のディレクトリまたはファイルのパス
        client_id: BotのクライアントID
        scopes: OAuth2スコープのリスト（デフォルト: ['bot', 'applications.commands']）

    Returns:
        生成された招待URL

    Example:
        >>> import mper
        >>> url = mper.generate_invite_url("./my_bot", client_id="123456789")
        >>> print(url)
    """
    import os

    if os.path.isfile(path):
        result = scan_file(path)
    else:
        result = scan_directory(path)

    permission_names = result['invite_link_permissions']
    permissions = calculate_permission_integer(permission_names)
    return create_invite_link(client_id, permissions, scopes)


def write_invite_link_to_file(invite_link: str, file_path: str = 'bot_invite_url.txt') -> None:
    """
    指定したファイルに招待リンクを追記する。
    
    Parameters:
    	invite_link (str): 追記する招待URL文字列。
    	file_path (str): 招待リンクを書き込むファイルのパス。存在しない場合は新規作成され、末尾に追記される。
    """
    with open(file_path, 'a') as file:
        file.write(invite_link + '\n')


def format_permissions_report(result: Dict, show_evidence: bool = True) -> str:
    """Format a human-readable permissions report with evidence."""
    lines = []
    lines.append("=" * 70)
    lines.append("Discord Bot Permission Scan Report")
    lines.append("=" * 70)
    lines.append("")

    lines.append(f"Files scanned: {result['files_scanned']}")
    lines.append(f"Files with errors: {result['files_with_errors']}")
    lines.append("")

    # PRIMARY: Method-based permissions with evidence
    evidence = result.get('evidence', {})
    if evidence and show_evidence:
        lines.append("-" * 70)
        lines.append("DETECTED PERMISSIONS (from method calls - PRIMARY)")
        lines.append("-" * 70)
        lines.append("")

        for perm in sorted(evidence.keys()):
            value = get_permission_value(perm)
            calls = evidence[perm]
            lines.append(f"{perm} (0x{value:X}):")

            # Group by file for cleaner output
            by_file: Dict[str, List[MethodCall]] = {}
            for file_path, call in calls:
                if file_path not in by_file:
                    by_file[file_path] = []
                by_file[file_path].append(call)

            for file_path, file_calls in by_file.items():
                # Show relative path if possible
                rel_path = os.path.basename(file_path)
                for call in file_calls:
                    chain = call.call_chain
                    lines.append(f"  {rel_path}:{call.line_number} -> {chain}()")
                    if call.description:
                        lines.append(f"    [{call.confidence}] {call.description}")
            lines.append("")
    elif result.get('inferred_permissions'):
        lines.append("-" * 70)
        lines.append("DETECTED PERMISSIONS (from method calls - PRIMARY)")
        lines.append("-" * 70)
        lines.append("")
        for perm in sorted(result['inferred_permissions']):
            value = get_permission_value(perm)
            lines.append(f"  {perm} (0x{value:X})")
        lines.append("")

    # SUPPLEMENTARY: @bot_has_permissions
    if result.get('bot_permissions'):
        lines.append("-" * 70)
        lines.append("EXPLICIT BOT PERMISSIONS (from @bot_has_permissions - SUPPLEMENTARY)")
        lines.append("-" * 70)
        lines.append("")
        for perm in sorted(result['bot_permissions']):
            value = get_permission_value(perm)
            lines.append(f"  {perm} (0x{value:X})")
        lines.append("")

    # REFERENCE ONLY: @has_permissions (NOT for invite link)
    if result.get('user_permissions'):
        lines.append("-" * 70)
        lines.append("USER PERMISSIONS (from @has_permissions - NOT for invite link)")
        lines.append("-" * 70)
        lines.append("NOTE: These are USER requirements, not BOT requirements.")
        lines.append("      They are NOT included in the invite link.")
        lines.append("")
        for perm in sorted(result['user_permissions']):
            value = get_permission_value(perm)
            lines.append(f"  {perm} (0x{value:X})")
        lines.append("")

    if result.get('warnings'):
        lines.append("-" * 70)
        lines.append("WARNINGS")
        lines.append("-" * 70)
        for warning in result['warnings'][:10]:
            lines.append(f"  {warning}")
        if len(result['warnings']) > 10:
            lines.append(f"  ... and {len(result['warnings']) - 10} more warnings")
        lines.append("")

    # Final summary: Invite link permissions
    invite_perms = result.get('invite_link_permissions', set())
    total_perms = calculate_permissions(invite_perms)
    lines.append("=" * 70)
    lines.append("INVITE LINK PERMISSIONS")
    lines.append("=" * 70)
    lines.append("Source: method-based detection + @bot_has_permissions")
    lines.append("")
    lines.append(f"  Permissions: {', '.join(sorted(invite_perms)) if invite_perms else 'None'}")
    lines.append(f"  Integer: {total_perms}")
    lines.append(f"  Hex: 0x{total_perms:X}")
    lines.append("")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Scan Discord bot code and generate invite links with required permissions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mper /path/to/bot 123456789012345678
  mper /path/to/bot 123456789012345678 --verbose
  mper /path/to/bot 123456789012345678 --no-inferred
  mper /path/to/bot 123456789012345678 --scope bot --scope applications.commands
  mper /path/to/bot 123456789012345678 --plain
        """
    )
    parser.add_argument('directory', type=str, help='Directory to scan')
    parser.add_argument('client_id', type=str, help='Client ID of the Discord bot')
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed output'
    )
    parser.add_argument(
        '--no-inferred',
        action='store_true',
        help='Only use declared permissions (from decorators), ignore inferred permissions'
    )
    parser.add_argument(
        '--exclude',
        type=str,
        nargs='*',
        default=[],
        help='Additional directories to exclude'
    )
    parser.add_argument(
        '--scope',
        type=str,
        nargs='*',
        default=['bot', 'applications.commands'],
        help='OAuth2 scopes for the invite link (default: bot applications.commands)'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='bot_invite_url.txt',
        help='Output file for the invite link (default: bot_invite_url.txt)'
    )
    parser.add_argument(
        '--report',
        action='store_true',
        help='Print a detailed permissions report'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    parser.add_argument(
        '--plain',
        action='store_true',
        help='Use plain text output (no styling or animations)'
    )

    args = parser.parse_args()

    # Initialize styled output
    from .cli_output import StyledOutput
    output = StyledOutput(no_color=args.no_color, plain=args.plain)

    # Print banner
    output.print_banner()

    # Validate directory
    if not os.path.isdir(args.directory):
        output.print_error(f"'{args.directory}' is not a valid directory")
        sys.exit(1)

    # Build exclude set
    exclude_dirs = DEFAULT_EXCLUDE_DIRS.copy()
    exclude_dirs.update(args.exclude)

    # Count files first for progress bar
    python_files = []
    for root, dirs, files in os.walk(args.directory):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))

    # Scan with progress bar
    output.print_scanning_start(args.directory)

    progress = output.create_progress()
    if progress:
        with progress:
            task = progress.add_task(
                "Scanning files...",
                total=len(python_files),
                current_file=""
            )
            result = scan_directory_with_progress(
                args.directory,
                exclude_dirs=exclude_dirs,
                include_inferred=not args.no_inferred,
                progress=progress,
                task_id=task,
                python_files=python_files
            )
    else:
        # Plain mode - use regular scan
        result = scan_directory(
            args.directory,
            exclude_dirs=exclude_dirs,
            include_inferred=not args.no_inferred,
            verbose=args.verbose
        )

    # Print scan completion
    output.print_scan_complete(result['files_scanned'], result['files_with_errors'])

    # Calculate bot permissions for invite link
    total_permissions = calculate_permissions(result['invite_link_permissions'])

    # Generate invite link
    invite_link = create_invite_link(args.client_id, total_permissions, args.scope)

    # Write to file
    write_invite_link_to_file(invite_link, args.output)

    # Output results
    if args.report:
        # Show detailed evidence table
        evidence = result.get('evidence', {})
        if evidence:
            output.print_permissions_table(evidence)

        # Show supplementary permissions
        if result.get('bot_permissions'):
            output.print_permissions_list(
                result['bot_permissions'],
                "Explicit Bot Permissions",
                "from @bot_has_permissions - SUPPLEMENTARY",
                style="blue"
            )

        # Show user permissions (reference only)
        if result.get('user_permissions'):
            output.print_permissions_list(
                result['user_permissions'],
                "User Permissions",
                "from @has_permissions - NOT for invite link",
                style="yellow"
            )

    # Print summary
    output.print_summary(
        len(result.get('inferred_permissions', set())),
        len(result.get('bot_permissions', set())),
        len(result.get('user_permissions', set())),
        total_permissions
    )

    # Print warnings
    output.print_warnings(result.get('warnings', []))

    # Print invite link
    output.print_invite_link(
        invite_link,
        result['invite_link_permissions'],
        total_permissions,
        args.output
    )


if __name__ == "__main__":
    main()