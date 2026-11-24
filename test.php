<?php
declare(strict_types=1);

// 仅用于本地隔离环境下的静态代码审计规则测试（SAST Benchmark）
if (($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    http_response_code(403);
    exit("Local only\n");
}

function get_db(): PDO
{
    $pdo = new PDO('sqlite::memory:');
    $pdo->exec("CREATE TABLE items (id INT, name TEXT, flag INT)");
    $pdo->exec("INSERT INTO items VALUES (1, 'alpha', 1), (2, 'beta', 0)");
    return $pdo;
}

// ==========================================
// 一、 XSS 漏洞（低 / 中 / 高 三种审计难度）
// ==========================================

// [XSS - 低难度] 直接源到汇（Source -> Sink），无中间处理与过滤
function xss_low(): void
{
    $q = $_GET['xss_low'] ?? '';
    echo "<div>" . $q . "</div>";
}

// [XSS - 中难度] 跨函数流转 + 局部字符替换/编码不足
function sanitize_xss_partial(string $input): string
{
    // 仅替换小写 script 标签，大小写绕过或事件处理器仍可触发
    return str_replace('<script>', '', $input);
}

function xss_medium(): void
{
    $raw = $_POST['xss_mid'] ?? '';
    $filtered = sanitize_xss_partial($raw);
    $output = sprintf('<span data-note="%s">Preview</span>', $filtered);
    echo $output;
}

// [XSS - 高难度] 多级数据重组、关联数组传递与上下文错配编码
function build_xss_context(array $bag): array
{
    return [
        'safe_html' => htmlspecialchars((string)($bag['label'] ?? ''), ENT_QUOTES, 'UTF-8'),
        // 误将仅针对 HTML 标签的过滤用于 JS 字符串上下文，且通过键名映射传递
        'js_slot'   => str_replace('</script>', '', (string)($bag['script_arg'] ?? '')),
    ];
}

function xss_high(): void
{
    $payload = [
        'label'      => $_GET['label'] ?? 'ok',
        'script_arg' => $_GET['js_arg'] ?? 'default_val',
    ];
    $ctx = build_xss_context($payload);
    echo "<p>{$ctx['safe_html']}</p>";
    echo "<script>var cfg = '" . $ctx['js_slot'] . "';</script>";
}

// ==========================================
// 二、 RCE 漏洞（低 / 中 / 高 三种审计难度）
// ==========================================

// [RCE - 低难度] 参数直接进入命令执行函数
function rce_low(): void
{
    $cmd = $_GET['rce_low'] ?? 'id';
    system($cmd);
}

// [RCE - 中难度] 经过白名单前缀判断但允许命令分隔符拼接
function rce_medium(): void
{
    $target = $_POST['rce_mid'] ?? '127.0.0.1';
    if (str_contains($target, '127.0.0.1') || str_starts_with($target, 'localhost')) {
        $fullCmd = "ping -c 1 " . $target;
        passthru($fullCmd);
    }
}

// [RCE - 高难度] 动态回调分发 + 间接参数解包 + 弱正则校验绕过
function dispatch_handler(string $fn, array $args): mixed
{
    // 校验仅检查字母与下划线，但传入的动态函数名或参数结构存在间接拼接路径
    if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $fn)) {
        return null;
    }
    return call_user_func_array($fn, $args);
}

function build_shell_command(string $action, string $arg): string
{
    $map = [
        'check' => 'echo status: ',
        'stat'  => 'uptime -p # ',
    ];
    $prefix = $map[$action] ?? 'echo ';
    // 拼接时未对 $arg 进行转义，且允许通过特殊字符逃逸
    return $prefix . $arg;
}

function rce_high(): void
{
    $action = $_GET['action'] ?? 'check';
    $arg    = $_GET['arg'] ?? 'ready';
    $line   = build_shell_command($action, $arg);
    dispatch_handler('shell_exec', [$line]);
}

// ==========================================
// 三、 SQL 注入漏洞（低 / 中 / 高 三种审计难度）
// ==========================================

// [SQLi - 低难度] 输入直接拼接到 SQL 查询字符串
function sqli_low(): void
{
    $id = $_GET['sqli_low'] ?? '1';
    $sql = "SELECT id, name FROM items WHERE id = " . $id;
    $stmt = get_db()->query($sql);
    echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
}

// [SQLi - 中难度] 经过类型转换/字符串拼接包装后再执行
function format_filter_clause(string $col, string $val): string
{
    $allowedCols = ['id', 'name', 'flag'];
    $safeCol = in_array($col, $allowedCols, true) ? $col : 'id';
    // $val 未参数化也未转义，直接拼入 LIKE / 比较子句
    return "{$safeCol} = '{$val}'";
}

function sqli_medium(): void
{
    $col = $_POST['col'] ?? 'name';
    $val = $_POST['val'] ?? 'alpha';
    $where = format_filter_clause($col, $val);
    $sql = "SELECT id, name, flag FROM items WHERE " . $where;
    $rows = get_db()->query($sql)->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode($rows);
}

// [SQLi - 高难度] 仓库模式封装 + 条件动态拼装 + 看似安全的参数化掩护
final class ItemRepository
{
    public function __construct(private PDO $pdo) {}

    public function search(array $criteria): array
    {
        $sql = "SELECT id, name, flag FROM items WHERE 1=1";
        $params = [];

        if (!empty($criteria['flag'])) {
            $sql .= " AND flag = :flag";
            $params[':flag'] = (int)$criteria['flag'];
        }

        // ORDER BY 方向或排序表达式通过动态映射拼装，存在注入风险
        if (!empty($criteria['order_expr'])) {
            $sql .= " ORDER BY " . $criteria['order_expr'];
        }

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

function sqli_high(): void
{
    $criteria = [
        'flag'       => $_GET['flag'] ?? null,
        'order_expr' => $_GET['order_by'] ?? 'id ASC',
    ];
    $repo = new ItemRepository(get_db());
    echo json_encode($repo->search($criteria));
}

// ==========================================
// 路由分发
// ==========================================
$route = $_GET['r'] ?? '';
match ($route) {
    'xss_low'   => xss_low(),
    'xss_mid'   => xss_medium(),
    'xss_high'  => xss_high(),
    'rce_low'   => rce_low(),
    'rce_mid'   => rce_medium(),
    'rce_high'  => rce_high(),
    'sqli_low'  => sqli_low(),
    'sqli_mid'  => sqli_medium(),
    'sqli_high' => sqli_high(),
    default     => print("Routes: xss_low, xss_mid, xss_high, rce_low, rce_mid, rce_high, sqli_low, sqli_mid, sqli_high\n"),
};