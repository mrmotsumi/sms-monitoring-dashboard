<?php
/**
 * SMS Monitoring Dashboard
 *
 * Real-time dashboard for monitoring SMS notification delivery across
 * multiple branches of a regulated financial platform.
 *
 * Features:
 * - Role-based access control (Admin, Director, Principal Officer, Manager)
 * - Branch-scoped queries for manager role
 * - Delivery rate analytics with 30-day trend chart
 * - Hourly heatmap of today's activity
 * - Event type breakdown (due_soon, overdue, issued, approved, etc.)
 * - Paginated SMS log with phone number masking
 * - CSV export with date range filtering
 *
 * Security:
 * - Session-based authentication
 * - Prepared statements throughout (no SQL injection)
 * - XSS prevention via htmlspecialchars()
 * - Phone number masking for privacy
 * - Role enforcement with HTTP 403 on violation
 *
 * @package  LoanManagementSystem
 * @author   github.com/mrmotsumi
 */

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// ── Security headers ──────────────────────────────────────────────────────────
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' cdnjs.cloudflare.com; style-src 'self' fonts.googleapis.com cdnjs.cloudflare.com 'unsafe-inline'; font-src fonts.gstatic.com cdnjs.cloudflare.com;");

session_start();

// ── Authentication ────────────────────────────────────────────────────────────
if (!isset($_SESSION['email'])) {
    header('Location: ../login.php');
    exit;
}

$role    = $_SESSION['role']    ?? null;
$branch  = $_SESSION['branch']  ?? null;
$user_id = $_SESSION['userid']  ?? null;

// ── Role-based access control ─────────────────────────────────────────────────
$allowedRoles = ['admin', 'director', 'principal_officer', 'manager'];
if (!in_array($role, $allowedRoles)) {
    http_response_code(403);
    exit;
}

// ── Database connection ───────────────────────────────────────────────────────
require('../config/databaseConfig.php');
if (!isset($conn) || ($conn instanceof mysqli && $conn->connect_error)) {
    error_log('SMS Dashboard: Database connection failed');
    http_response_code(503);
    die('Service temporarily unavailable. Please try again later.');
}

// ── Table existence checks ────────────────────────────────────────────────────
$smsLogsExists   = $conn->query("SHOW TABLES LIKE 'sms_logs'")->num_rows   > 0;
$eventLogsExists = $conn->query("SHOW TABLES LIKE 'event_logs'")->num_rows > 0;

// ── Filters ───────────────────────────────────────────────────────────────────
$filterFrom = $_GET['from'] ?? date('Y-m-01');
$filterTo   = $_GET['to']   ?? date('Y-m-d');
$filterPage = max(1, (int)($_GET['page'] ?? 1));
$perPage    = 25;
$offset     = ($filterPage - 1) * $perPage;

// ── Branch scope (manager sees own branch only) ───────────────────────────────
$branchJoin  = "LEFT JOIN loan l ON sl.loan_id = l.loanId
                LEFT JOIN customer c ON l.national_id = c.national_id
                LEFT JOIN branches b ON c.branch = b.branch_id";
$branchWhere  = '';
$branchParams = [];
$branchTypes  = '';
if ($role === 'manager' && $branch) {
    $branchWhere    = 'AND b.branch_name = ?';
    $branchParams[] = $branch;
    $branchTypes   .= 's';
}

// ── Stats ─────────────────────────────────────────────────────────────────────
$stats = [
    'total_sent'    => 0,
    'success_count' => 0,
    'failed_count'  => 0,
    'unique_loans'  => 0,
    'unique_phones' => 0,
    'avg_attempts'  => 0,
    'active_days'   => 0,
];

if ($smsLogsExists) {
    $q  = "SELECT COUNT(*) AS total_sent,
                  SUM(status='sent')   AS success_count,
                  SUM(status='failed') AS failed_count,
                  COUNT(DISTINCT sl.loan_id)  AS unique_loans,
                  COUNT(DISTINCT sl.phone)    AS unique_phones,
                  ROUND(AVG(sl.attempt), 1)   AS avg_attempts,
                  COUNT(DISTINCT DATE(sl.created_at)) AS active_days
           FROM sms_logs sl {$branchJoin}
           WHERE DATE(sl.created_at) BETWEEN ? AND ? {$branchWhere}";
    $st = $conn->prepare($q);
    if ($st) {
        $st->bind_param('ss' . $branchTypes, ...array_merge([$filterFrom, $filterTo], $branchParams));
        $st->execute();
        $stats = $st->get_result()->fetch_assoc();
        $st->close();
    }
}

// ── Event type breakdown ──────────────────────────────────────────────────────
$typeBreakdown = [];
if ($eventLogsExists) {
    $bj = ($role === 'manager' && $branch)
        ? "LEFT JOIN loan l ON el.loan_id=l.loanId
           LEFT JOIN customer c ON l.national_id=c.national_id
           LEFT JOIN branches b ON c.branch=b.branch_id"
        : "";
    $bw = ($role === 'manager' && $branch) ? "AND b.branch_name=?" : "";
    $q  = "SELECT el.event_type, COUNT(*) AS cnt
           FROM event_logs el {$bj}
           WHERE DATE(el.created_at) BETWEEN ? AND ?
             AND el.event_type IN (
                 'loan.due_soon_3days','loan.due_today','loan.overdue',
                 'loan.issued','loan.approved','loan.disbursed',
                 'loan.extended','loan.drafted'
             )
           {$bw}
           GROUP BY el.event_type
           ORDER BY cnt DESC";
    $st = $conn->prepare($q);
    if ($st) {
        $st->bind_param('ss' . $branchTypes, ...array_merge([$filterFrom, $filterTo], $branchParams));
        $st->execute();
        $res = $st->get_result();
        while ($r = $res->fetch_assoc()) $typeBreakdown[] = $r;
        $st->close();
    }
}

// ── 30-day chart data ─────────────────────────────────────────────────────────
$chartData = [];
if ($smsLogsExists) {
    $q  = "SELECT DATE(sl.created_at) AS send_date,
                  COUNT(*)            AS cnt,
                  SUM(status='sent')   AS sent_cnt,
                  SUM(status='failed') AS fail_cnt
           FROM sms_logs sl {$branchJoin}
           WHERE sl.created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY) {$branchWhere}
           GROUP BY DATE(sl.created_at)
           ORDER BY send_date";
    $st = $conn->prepare($q);
    if ($st) {
        if (!empty($branchParams)) $st->bind_param($branchTypes, ...$branchParams);
        $st->execute();
        $res = $st->get_result();
        while ($r = $res->fetch_assoc()) $chartData[] = $r;
        $st->close();
    }
}

// ── Hourly heatmap ────────────────────────────────────────────────────────────
$hourlyData = array_fill(0, 24, 0);
if ($smsLogsExists) {
    $q  = "SELECT HOUR(sl.created_at) AS hr, COUNT(*) AS cnt
           FROM sms_logs sl {$branchJoin}
           WHERE DATE(sl.created_at) = CURDATE() {$branchWhere}
           GROUP BY HOUR(sl.created_at)";
    $st = $conn->prepare($q);
    if ($st) {
        if (!empty($branchParams)) $st->bind_param($branchTypes, ...$branchParams);
        $st->execute();
        $res = $st->get_result();
        while ($r = $res->fetch_assoc()) $hourlyData[(int)$r['hr']] = (int)$r['cnt'];
        $st->close();
    }
}

// ── Today's counters ──────────────────────────────────────────────────────────
$failedTodayCount = 0;
$todayTotal       = 0;
if ($smsLogsExists) {
    foreach ([['failed', 'failedTodayCount'], ['', 'todayTotal']] as [$s, $var]) {
        $sw = $s ? "sl.status='failed' AND" : "";
        $q  = "SELECT COUNT(*) AS c
               FROM sms_logs sl {$branchJoin}
               WHERE {$sw} DATE(sl.created_at) = CURDATE() {$branchWhere}";
        $st = $conn->prepare($q);
        if ($st) {
            if (!empty($branchParams)) $st->bind_param($branchTypes, ...$branchParams);
            $st->execute();
            $$var = (int)$st->get_result()->fetch_assoc()['c'];
            $st->close();
        }
    }
}

// ── Main log ──────────────────────────────────────────────────────────────────
$logs      = [];
$totalRows = 0;
if ($smsLogsExists) {
    $q  = "SELECT sl.id, sl.loan_id, sl.phone, sl.message, sl.status,
                  sl.error, sl.message_id, sl.attempt, sl.created_at,
                  l.loan_id_display, l.full_loan_number, l.pawn_type,
                  CONCAT(c.firstname,' ',c.lastname) AS customer_name,
                  c.national_id, b.branch_name,
                  (SELECT el.event_type FROM event_logs el
                   WHERE el.loan_id = sl.loan_id
                   ORDER BY ABS(TIMESTAMPDIFF(SECOND, el.created_at, sl.created_at)) ASC
                   LIMIT 1) AS event_type
           FROM sms_logs sl {$branchJoin}
           WHERE DATE(sl.created_at) BETWEEN ? AND ? {$branchWhere}
           ORDER BY sl.created_at DESC
           LIMIT ? OFFSET ?";
    $st = $conn->prepare($q);
    if ($st) {
        $st->bind_param(
            'ss' . $branchTypes . 'ii',
            ...array_merge([$filterFrom, $filterTo], $branchParams, [$perPage, $offset])
        );
        $st->execute();
        $res = $st->get_result();
        while ($r = $res->fetch_assoc()) $logs[] = $r;
        $st->close();
    }

    $q  = "SELECT COUNT(*) AS total
           FROM sms_logs sl {$branchJoin}
           WHERE DATE(sl.created_at) BETWEEN ? AND ? {$branchWhere}";
    $st = $conn->prepare($q);
    if ($st) {
        $st->bind_param('ss' . $branchTypes, ...array_merge([$filterFrom, $filterTo], $branchParams));
        $st->execute();
        $totalRows = (int)$st->get_result()->fetch_assoc()['total'];
        $st->close();
    }
}

$totalPages  = max(1, ceil($totalRows / $perPage));
$successRate = $stats['total_sent'] > 0
    ? round(($stats['success_count'] / $stats['total_sent']) * 100, 1)
    : 0;

// ── Helper functions ──────────────────────────────────────────────────────────

/**
 * Human-readable label for loan event types.
 */
function evtLabel(?string $t): string {
    return [
        'loan.due_soon_3days' => 'Due in 3 Days',
        'loan.due_today'      => 'Due Today',
        'loan.overdue'        => 'Overdue',
        'loan.issued'         => 'Loan Issued',
        'loan.approved'       => 'Approved',
        'loan.disbursed'      => 'Disbursed',
        'loan.extended'       => 'Extended',
        'loan.drafted'        => 'Drafted',
        'loan.closed'         => 'Closed',
    ][$t] ?? ($t ? ucwords(str_replace(['.', '_'], ' ', $t)) : 'Notification');
}

/**
 * CSS colours and icon for each event type.
 * Returns: [bg_rgba, text_colour, border_colour, fa_icon_class]
 */
function evtMeta(?string $t): array {
    return [
        'loan.due_soon_3days' => ['rgba(245,158,11,.15)',  '#fbbf24', '#f59e0b', 'fa-hourglass-half'],
        'loan.due_today'      => ['rgba(239,68,68,.15)',   '#f87171', '#ef4444', 'fa-bell'],
        'loan.overdue'        => ['rgba(236,72,153,.15)',  '#f472b6', '#ec4899', 'fa-exclamation-circle'],
        'loan.extended'       => ['rgba(139,92,246,.15)',  '#a78bfa', '#8b5cf6', 'fa-clock'],
        'loan.issued'         => ['rgba(59,130,246,.15)',  '#60a5fa', '#3b82f6', 'fa-file-invoice-dollar'],
        'loan.approved'       => ['rgba(16,185,129,.15)',  '#34d399', '#10b981', 'fa-check-circle'],
        'loan.disbursed'      => ['rgba(13,148,136,.15)',  '#2dd4bf', '#0d9488', 'fa-money-bill-wave'],
        'loan.closed'         => ['rgba(100,116,139,.15)', '#94a3b8', '#64748b', 'fa-lock'],
        'loan.drafted'        => ['rgba(14,165,233,.15)',  '#38bdf8', '#0ea5e9', 'fa-file-pen'],
    ][$t] ?? ['rgba(100,116,139,.15)', '#94a3b8', '#64748b', 'fa-comment'];
}

/**
 * Mask phone number for display — shows first 3 and last 4 digits only.
 * Privacy protection for customer data.
 */
function maskPhone(string $p): string {
    $p = preg_replace('/\D/', '', $p);
    return strlen($p) >= 8 ? substr($p, 0, 3) . '·····' . substr($p, -4) : $p;
}

/**
 * Short label for loan type.
 */
function loanTypeShort(?string $t): string {
    return match($t) {
        'type_a' => 'T-A',
        'type_b' => 'T-B',
        'type_c' => 'T-C',
        default  => '—',
    };
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SMS Dashboard · Loan Management System</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700&family=Fraunces:opsz,wght@9..144,300;9..144,400;9..144,600&family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
    --sb-w:260px;
    --forest:#0C1F0E;--forest-2:#112614;--forest-3:#162D1A;
    --gold:#D4A017;--gold-l:#F0C040;--gold-dim:rgba(212,160,23,.1);--gold-glow:rgba(212,160,23,.22);
    --green:#22c55e;--green-dim:rgba(34,197,94,.1);
    --red:#ef4444;--red-dim:rgba(239,68,68,.1);
    --amber:#f59e0b;
    --page:#0B170C;--surf:#131E14;--surf-2:#182019;--surf-3:#1d2b1e;
    --card:#162018;--cb:rgba(255,255,255,.065);--cb-hi:rgba(212,160,23,.28);
    --t1:#eef2ee;--t2:rgba(238,242,238,.72);--t3:rgba(238,242,238,.4);--t4:rgba(238,242,238,.18);
    --r:12px;--rs:8px;--rx:5px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'DM Sans',sans-serif;background:var(--page);color:var(--t1);font-size:14px;line-height:1.6;min-height:100vh}
.layout{display:flex;min-height:100vh}
.main{margin-left:var(--sb-w);flex:1;min-width:0;display:flex;flex-direction:column}
@media(max-width:1024px){.main{margin-left:0}}
.topbar{position:sticky;top:0;z-index:100;background:rgba(11,23,12,.88);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid var(--cb);padding:13px 26px;display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;}
.tb-left{display:flex;align-items:center;gap:12px}
.crumb{font-size:11px;color:var(--t4);display:flex;align-items:center;gap:5px}
.crumb a{color:var(--t3);text-decoration:none;transition:color .15s}
.crumb a:hover{color:var(--gold)}
.page-title{font-family:'Fraunces',serif;font-size:17px;font-weight:600;color:var(--t1);letter-spacing:-.3px;margin-top:2px}
.page-title .acc{color:var(--gold)}
.tb-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.chip{display:inline-flex;align-items:center;gap:5px;padding:4px 11px;border-radius:20px;font-size:10.5px;font-weight:600;border:1px solid;font-family:'DM Mono',monospace}
.chip-g{background:var(--gold-dim);border-color:rgba(212,160,23,.22);color:var(--gold)}
.chip-gr{background:var(--green-dim);border-color:rgba(34,197,94,.22);color:var(--green)}
.chip-r{background:var(--red-dim);border-color:rgba(239,68,68,.22);color:var(--red)}
.chip-f{background:rgba(37,117,44,.12);border-color:rgba(37,117,44,.25);color:#4ade80}
.live-dot{width:5px;height:5px;border-radius:50%;background:var(--green);animation:lpulse 2.5s infinite;flex-shrink:0}
@keyframes lpulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(34,197,94,.4)}50%{opacity:.8;box-shadow:0 0 0 5px rgba(34,197,94,0)}}
.sb-tog{display:none;width:32px;height:32px;background:var(--surf-2);border:1px solid var(--cb);border-radius:var(--rx);align-items:center;justify-content:center;cursor:pointer;color:var(--t2);font-size:12px;flex-shrink:0}
@media(max-width:1024px){.sb-tog{display:flex}}
.content{padding:22px 26px 48px;flex:1}
.notice{display:flex;align-items:flex-start;gap:9px;padding:12px 15px;border-radius:var(--rs);margin-bottom:14px;font-size:12.5px;border:1px solid;animation:fsi .3s ease both}
.nw{background:rgba(245,158,11,.07);border-color:rgba(245,158,11,.2);color:#fbbf24}
.ne{background:rgba(239,68,68,.07);border-color:rgba(239,68,68,.2);color:#f87171}
.notice code{background:rgba(255,255,255,.08);padding:1px 5px;border-radius:3px;font-family:'DM Mono',monospace;font-size:11px;color:inherit}
.fbar{background:var(--card);border:1px solid var(--cb);border-radius:var(--r);padding:13px 17px;display:flex;align-items:center;gap:11px;flex-wrap:wrap;margin-bottom:22px;animation:fsi .35s ease both}
.fg{display:flex;align-items:center;gap:6px}
.fg label{font-size:10px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.6px;white-space:nowrap}
.fg input[type=date]{height:32px;background:var(--surf-2);border:1px solid var(--cb);border-radius:var(--rx);padding:0 9px;font-size:12.5px;font-family:'DM Sans',sans-serif;color:var(--t1);outline:none;cursor:pointer;transition:border-color .15s;color-scheme:dark}
.fg input:focus{border-color:var(--gold)}
.fb{height:32px;padding:0 15px;border:none;border-radius:var(--rx);font-size:12.5px;font-family:'DM Sans',sans-serif;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:5px;text-decoration:none;transition:all .15s;letter-spacing:.01em}
.fb.pri{background:var(--gold);color:var(--forest)}.fb.pri:hover{background:var(--gold-l)}
.fb.gho{background:transparent;border:1px solid var(--cb);color:var(--t2)}.fb.gho:hover{border-color:var(--gold-glow);color:var(--gold)}
.fb.exp{background:rgba(29,92,34,.55);color:#86efac;border:1px solid rgba(37,117,44,.25);margin-left:auto}.fb.exp:hover{background:rgba(37,117,44,.6)}
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:13px;margin-bottom:22px}
.sc{background:var(--card);border:1px solid var(--cb);border-radius:var(--r);padding:17px 19px 15px;position:relative;overflow:hidden;transition:transform .2s,border-color .2s;animation:fsi .4s ease both}
.sc:hover{transform:translateY(-3px);border-color:var(--cb-hi)}
.sc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;opacity:0;transition:opacity .2s}
.sc:hover::before{opacity:1}
.gold-t::before{background:linear-gradient(90deg,var(--gold),var(--gold-l))}
.grn-t::before{background:linear-gradient(90deg,#22c55e,#4ade80)}
.red-t::before{background:linear-gradient(90deg,#ef4444,#f87171)}
.tea-t::before{background:linear-gradient(90deg,#0d9488,#2dd4bf)}
.blu-t::before{background:linear-gradient(90deg,#3b82f6,#60a5fa)}
.slt-t::before{background:linear-gradient(90deg,#64748b,#94a3b8)}
.sico{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:12px;margin-bottom:11px}
.ig{background:var(--gold-dim);color:var(--gold)}.igr{background:var(--green-dim);color:var(--green)}.ir{background:var(--red-dim);color:var(--red)}
.it{background:rgba(13,148,136,.12);color:#2dd4bf}.ib{background:rgba(59,130,246,.12);color:#60a5fa}.is{background:rgba(100,116,139,.12);color:#94a3b8}
.slbl{font-size:9.5px;font-weight:600;color:var(--t3);text-transform:uppercase;letter-spacing:.7px;margin-bottom:3px}
.sval{font-size:25px;font-weight:600;font-family:'DM Mono',monospace;color:var(--t1);line-height:1;letter-spacing:-.02em}
.ssub{font-size:11px;color:var(--t3);margin-top:4px}
.rate-wrap{display:inline-flex;align-items:center;gap:9px}
.rate-svg{width:42px;height:42px;flex-shrink:0}
.rate-svg circle{fill:none;stroke-width:4;stroke-linecap:round}
.rate-svg .bg{stroke:rgba(255,255,255,.07)}
.rate-svg .fill{stroke:#22c55e;transition:stroke-dashoffset .9s ease;transform:rotate(-90deg);transform-origin:50% 50%}
.crow{display:grid;grid-template-columns:1fr 298px;gap:14px;margin-bottom:22px}
@media(max-width:900px){.crow{grid-template-columns:1fr}}
.cc{background:var(--card);border:1px solid var(--cb);border-radius:var(--r);padding:19px 21px;animation:fsi .45s ease both}
.ctitle{font-family:'Fraunces',serif;font-size:13px;font-weight:600;color:var(--t1);margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;gap:8px}
.ctitle i{color:var(--gold);font-size:11px}
.cl{display:flex;gap:12px;font-size:10px;color:var(--t3)}
.cl span{display:flex;align-items:center;gap:3px}
.cldot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.hmap{display:grid;grid-template-columns:repeat(24,1fr);gap:3px;margin-top:10px}
.hm{height:26px;border-radius:3px;cursor:pointer;transition:opacity .15s}
.hm:hover{opacity:.75}
.hmlbl{display:flex;justify-content:space-between;margin-top:4px;font-size:8.5px;color:var(--t4);font-family:'DM Mono',monospace}
.tlg{display:flex;flex-direction:column;gap:1px}
.trow{display:flex;align-items:center;justify-content:space-between;padding:6px 9px;border-radius:var(--rx);transition:background .15s;cursor:default}
.trow:hover{background:var(--surf-2)}
.tleft{display:flex;align-items:center;gap:7px}
.tdot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.tname{font-size:11.5px;color:var(--t2)}
.tright{display:flex;align-items:center;gap:7px}
.tbar-w{width:54px;height:3px;background:var(--surf-3);border-radius:2px;overflow:hidden}
.tbar{height:100%;border-radius:2px;transition:width .6s ease}
.tn{font-family:'DM Mono',monospace;font-size:11px;color:var(--t1);font-weight:500;min-width:26px;text-align:right}
.tp{font-size:10px;color:var(--t3);min-width:26px;text-align:right}
.lsec{background:var(--card);border:1px solid var(--cb);border-radius:var(--r);overflow:hidden;animation:fsi .5s ease both}
.lhdr{padding:13px 19px;border-bottom:1px solid var(--cb);background:var(--surf);display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.lhtitle{font-family:'Fraunces',serif;font-size:13px;font-weight:600;display:flex;align-items:center;gap:6px;color:var(--t1)}
.lhtitle i{color:var(--gold)}
.cpill{background:var(--surf-3);color:var(--t3);font-size:10px;font-family:'DM Mono',monospace;padding:3px 9px;border-radius:20px;border:1px solid var(--cb)}
.tscr{overflow-x:auto}
table.lt{width:100%;border-collapse:collapse;font-size:12px}
table.lt thead tr{background:var(--surf-2)}
table.lt th{padding:9px 13px;text-align:left;font-weight:600;font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;white-space:nowrap;border-bottom:1px solid var(--cb)}
table.lt td{padding:10px 13px;border-bottom:1px solid rgba(255,255,255,.035);vertical-align:middle;color:var(--t2)}
table.lt tbody tr{transition:background .12s}
table.lt tbody tr:hover{background:var(--surf-2)}
table.lt tbody tr:last-child td{border-bottom:none}
table.lt tr.rf{background:rgba(239,68,68,.04)}
table.lt tr.rf:hover{background:rgba(239,68,68,.08)}
.rn{font-family:'DM Mono',monospace;font-size:10px;color:var(--t4)}
.tdate{font-weight:500;font-size:11.5px;color:var(--t1)}
.ttime{font-size:10px;color:var(--t3);font-family:'DM Mono',monospace;margin-top:1px}
.tname-c{font-weight:500;font-size:12px;color:var(--t1)}
.tid{font-size:10px;color:var(--t3);font-family:'DM Mono',monospace;margin-top:1px}
.tloan{font-weight:600;font-size:11px;color:#60a5fa;letter-spacing:.01em}
.ttype{display:inline-block;font-size:9px;background:var(--surf-3);color:var(--t3);padding:1px 5px;border-radius:3px;margin-top:2px;font-family:'DM Mono',monospace}
.epill{display:inline-flex;align-items:center;gap:3px;padding:3px 9px;border-radius:20px;font-size:10px;font-weight:600;white-space:nowrap}
.spill{display:inline-flex;align-items:center;gap:3px;padding:3px 9px;border-radius:20px;font-size:10px;font-weight:600;border:1px solid}
.ssent{background:var(--green-dim);color:var(--green);border-color:rgba(34,197,94,.2)}
.sfail{background:var(--red-dim);color:var(--red);border-color:rgba(239,68,68,.2)}
.ab{display:inline-block;background:var(--surf-3);color:var(--t3);font-family:'DM Mono',monospace;font-size:10px;padding:2px 6px;border-radius:3px;border:1px solid var(--cb)}
.ab.rt{background:rgba(245,158,11,.1);color:var(--amber);border-color:rgba(245,158,11,.2)}
.ph{font-family:'DM Mono',monospace;font-size:10.5px;color:var(--t3);letter-spacing:.03em}
.mprev{max-width:210px;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer;font-size:11.5px;transition:color .15s}
.mprev:hover{color:var(--t1);text-decoration:underline dotted rgba(212,160,23,.5)}
.etxt{font-size:10px;color:#f87171;font-style:italic;margin-top:2px;display:block;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msgid{font-size:9px;color:var(--t4);font-family:'DM Mono',monospace;margin-top:2px}
.empty{padding:56px 20px;text-align:center}
.eico{width:52px;height:52px;border-radius:12px;background:var(--surf-2);display:flex;align-items:center;justify-content:center;font-size:20px;color:var(--t4);margin:0 auto 14px}
.empty h3{font-size:14px;color:var(--t2);margin-bottom:5px}
.empty p{font-size:12px;color:var(--t3)}
.pager{display:flex;align-items:center;justify-content:space-between;padding:12px 19px;border-top:1px solid var(--cb);flex-wrap:wrap;gap:8px}
.pinfo{font-size:11px;color:var(--t3);font-family:'DM Mono',monospace}
.plinks{display:flex;gap:3px}
.pgb{width:28px;height:28px;display:flex;align-items:center;justify-content:center;border:1px solid var(--cb);border-radius:var(--rx);font-size:11px;color:var(--t2);text-decoration:none;transition:all .15s;background:transparent;font-family:'DM Mono',monospace}
.pgb:hover{border-color:var(--gold-glow);color:var(--gold)}
.pgb.on{background:var(--gold);color:var(--forest);border-color:var(--gold);font-weight:600}
.pgb.off{opacity:.3;pointer-events:none}
#mm{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}
#mm.open{display:flex}
.mbox{background:var(--card);border:1px solid var(--cb-hi);border-radius:var(--r);padding:24px;max-width:470px;width:94%;animation:min .25s cubic-bezier(.34,1.56,.64,1) both;box-shadow:0 24px 64px rgba(0,0,0,.7)}
.mhead{display:flex;align-items:center;gap:10px;margin-bottom:15px}
.mhico{width:32px;height:32px;border-radius:7px;background:var(--gold-dim);display:flex;align-items:center;justify-content:center;font-size:13px;color:var(--gold);flex-shrink:0}
.mtitle{font-family:'Fraunces',serif;font-size:14px;font-weight:600;color:var(--t1)}
.msub{font-size:11px;color:var(--t3);margin-top:1px}
.mbody{background:var(--surf);border:1px solid var(--cb);border-radius:var(--rs);padding:14px;font-size:12.5px;line-height:1.85;color:var(--t1);white-space:pre-wrap;word-break:break-word;max-height:340px;overflow-y:auto;font-family:'DM Mono',monospace;letter-spacing:.01em;scrollbar-width:thin;scrollbar-color:var(--gold-glow) transparent}
.mfoot{margin-top:14px;display:flex;justify-content:flex-end}
.mclose{padding:7px 16px;background:transparent;border:1px solid var(--cb);color:var(--t2);border-radius:var(--rx);font-size:12px;font-family:'DM Sans',sans-serif;cursor:pointer;transition:all .15s}
.mclose:hover{border-color:var(--cb-hi);color:var(--t1)}
@keyframes fsi{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:translateY(0)}}
@keyframes min{from{opacity:0;transform:scale(.93) translateY(8px)}to{opacity:1;transform:scale(1) translateY(0)}}
.sgrid .sc:nth-child(1){animation-delay:.05s}.sgrid .sc:nth-child(2){animation-delay:.1s}
.sgrid .sc:nth-child(3){animation-delay:.15s}.sgrid .sc:nth-child(4){animation-delay:.2s}
.sgrid .sc:nth-child(5){animation-delay:.25s}.sgrid .sc:nth-child(6){animation-delay:.3s}
@media(max-width:680px){.content{padding:14px}.sgrid{grid-template-columns:repeat(2,1fr)}.fbar{flex-direction:column;align-items:stretch}.fb.exp{margin-left:0}.topbar{padding:11px 14px}}
</style>
</head>
<body>

<div class="layout">

<?php
$sp = '../includes/sidebar.php';
if (file_exists($sp)) include_once($sp);
?>

<div class="main">

<!-- Topbar -->
<div class="topbar">
    <div class="tb-left">
        <button class="sb-tog" onclick="document.getElementById('sidebar')?.classList.toggle('sb-open')">
            <i class="fas fa-bars"></i>
        </button>
        <div>
            <div class="crumb">
                <a href="dashboard.php">Home</a>
                <i class="fas fa-chevron-right" style="font-size:8px;"></i>
                <span>Operations</span>
                <i class="fas fa-chevron-right" style="font-size:8px;"></i>
                <span style="color:var(--gold);">SMS Dashboard</span>
            </div>
            <div class="page-title">
                <i class="fas fa-comment-dots" style="font-size:14px;margin-right:6px;color:var(--gold);"></i>
                SMS <span class="acc">Reminder</span> Dashboard
            </div>
        </div>
    </div>
    <div class="tb-right">
        <?php if ($role === 'manager' && $branch): ?>
            <span class="chip chip-f">
                <i class="fas fa-store" style="font-size:8px;"></i>
                <?= htmlspecialchars($branch) ?>
            </span>
        <?php endif; ?>
        <span class="chip chip-g">
            <i class="fas fa-calendar" style="font-size:8px;"></i>
            <?= date('j M Y') ?>
        </span>
        <?php if ($todayTotal > 0): ?>
            <span class="chip chip-gr">
                <span class="live-dot"></span>
                <?= number_format($todayTotal) ?> today
            </span>
        <?php endif; ?>
        <?php if ($failedTodayCount > 0): ?>
            <span class="chip chip-r">
                <i class="fas fa-exclamation-circle" style="font-size:8px;"></i>
                <?= $failedTodayCount ?> failed
            </span>
        <?php endif; ?>
    </div>
</div>

<div class="content">

<?php if (!$smsLogsExists): ?>
    <div class="notice nw">
        <i class="fas fa-info-circle" style="flex-shrink:0;margin-top:2px;font-size:13px;"></i>
        <div>
            <strong>sms_logs not yet created.</strong>
            <code>LoanEventListener::ensureTablesExist()</code> auto-creates it on first SMS dispatch.
        </div>
    </div>
<?php endif; ?>

<?php if (!$eventLogsExists): ?>
    <div class="notice ne">
        <i class="fas fa-triangle-exclamation" style="flex-shrink:0;margin-top:2px;font-size:13px;"></i>
        <div>
            <strong>event_logs not yet created.</strong>
            Auto-created by <code>ensureTablesExist()</code> on first event.
        </div>
    </div>
<?php endif; ?>

<!-- Filter bar -->
<form method="GET" class="fbar">
    <div class="fg">
        <label>From</label>
        <input type="date" name="from" value="<?= htmlspecialchars($filterFrom) ?>" max="<?= date('Y-m-d') ?>">
    </div>
    <div class="fg">
        <label>To</label>
        <input type="date" name="to" value="<?= htmlspecialchars($filterTo) ?>" max="<?= date('Y-m-d') ?>">
    </div>
    <button type="submit" class="fb pri"><i class="fas fa-filter"></i>Apply</button>
    <a href="?from=<?= date('Y-m-01') ?>&to=<?= date('Y-m-d') ?>" class="fb gho">
        <i class="fas fa-undo"></i>Reset
    </a>
    <a href="sms_export.php?from=<?= urlencode($filterFrom) ?>&to=<?= urlencode($filterTo) ?><?= $branch ? '&branch=' . urlencode($branch) : '' ?>"
       class="fb exp" target="_blank">
        <i class="fas fa-file-csv"></i>Export
    </a>
</form>

<!-- Stats grid -->
<div class="sgrid">
    <div class="sc gold-t">
        <div class="sico ig"><i class="fas fa-paper-plane"></i></div>
        <div class="slbl">Total Sent</div>
        <div class="sval" id="anim-tot"><?= number_format((int)$stats['total_sent']) ?></div>
        <div class="ssub"><?= $stats['active_days'] ?> active days in range</div>
    </div>
    <div class="sc grn-t">
        <div class="sico igr"><i class="fas fa-signal"></i></div>
        <div class="slbl">Delivery Rate</div>
        <div class="rate-wrap">
            <svg class="rate-svg" viewBox="0 0 42 42">
                <circle class="bg" cx="21" cy="21" r="17"/>
                <circle class="fill" cx="21" cy="21" r="17"
                    stroke-dasharray="106.8"
                    stroke-dashoffset="<?= round(106.8 * (1 - $successRate / 100), 1) ?>"/>
            </svg>
            <div>
                <div class="sval"><?= $successRate ?>%</div>
                <div class="ssub"><?= number_format((int)$stats['success_count']) ?> delivered</div>
            </div>
        </div>
    </div>
    <div class="sc red-t">
        <div class="sico ir"><i class="fas fa-times-circle"></i></div>
        <div class="slbl">Failed</div>
        <div class="sval" style="<?= $stats['failed_count'] > 0 ? 'color:var(--red);' : '' ?>">
            <?= number_format((int)$stats['failed_count']) ?>
        </div>
        <div class="ssub">
            <?= $stats['total_sent'] > 0
                ? round(($stats['failed_count'] / $stats['total_sent']) * 100, 1)
                : 0 ?>% failure rate
        </div>
    </div>
    <div class="sc tea-t">
        <div class="sico it"><i class="fas fa-file-invoice-dollar"></i></div>
        <div class="slbl">Unique Loans</div>
        <div class="sval"><?= number_format((int)$stats['unique_loans']) ?></div>
        <div class="ssub">loans notified</div>
    </div>
    <div class="sc blu-t">
        <div class="sico ib"><i class="fas fa-mobile-alt"></i></div>
        <div class="slbl">Recipients</div>
        <div class="sval"><?= number_format((int)$stats['unique_phones']) ?></div>
        <div class="ssub">unique phones</div>
    </div>
    <div class="sc slt-t">
        <div class="sico is"><i class="fas fa-redo"></i></div>
        <div class="slbl">Avg Attempts</div>
        <div class="sval"><?= number_format((float)$stats['avg_attempts'], 1) ?></div>
        <div class="ssub">per message (max 3)</div>
    </div>
</div>

<!-- Charts -->
<div class="crow">
    <div class="cc">
        <div class="ctitle">
            <span><i class="fas fa-chart-area"></i> 30-Day Send Volume</span>
            <div class="cl">
                <span><span class="cldot" style="background:var(--gold);"></span>Sent</span>
                <span><span class="cldot" style="background:var(--red);"></span>Failed</span>
            </div>
        </div>
        <div style="position:relative;width:100%;height:185px;">
            <canvas id="vc" role="img" aria-label="Daily SMS volume over last 30 days">Volume data.</canvas>
        </div>
        <div style="margin-top:16px;">
            <div style="font-size:9.5px;color:var(--t3);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px;">
                Today's Activity by Hour
            </div>
            <div class="hmap" id="hmg"></div>
            <div class="hmlbl">
                <span>12am</span><span>6am</span><span>12pm</span><span>6pm</span><span>11pm</span>
            </div>
        </div>
    </div>
    <div class="cc" style="display:flex;flex-direction:column;">
        <div class="ctitle"><span><i class="fas fa-layer-group"></i> By Event Type</span></div>
        <?php if (!empty($typeBreakdown)):
            $totBk = array_sum(array_column($typeBreakdown, 'cnt')); ?>
        <div style="position:relative;width:100%;height:115px;margin-bottom:12px;">
            <canvas id="tc" role="img" aria-label="Event type distribution">Event types.</canvas>
        </div>
        <div class="tlg">
            <?php foreach ($typeBreakdown as $tb):
                $m   = evtMeta($tb['event_type']);
                $pct = $totBk > 0 ? round(($tb['cnt'] / $totBk) * 100) : 0;
                $w   = max(4, $pct);
            ?>
            <div class="trow">
                <div class="tleft">
                    <span class="tdot" style="background:<?= $m[2] ?>;"></span>
                    <span class="tname"><?= evtLabel($tb['event_type']) ?></span>
                </div>
                <div class="tright">
                    <div class="tbar-w">
                        <div class="tbar" style="width:<?= $w ?>%;background:<?= $m[2] ?>;opacity:.65;"></div>
                    </div>
                    <span class="tn"><?= number_format((int)$tb['cnt']) ?></span>
                    <span class="tp"><?= $pct ?>%</span>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
        <div style="flex:1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:7px;color:var(--t3);font-size:12px;padding:20px 0;">
            <i class="fas fa-chart-pie" style="font-size:26px;opacity:.15;"></i>
            No event data for this period
        </div>
        <?php endif; ?>
    </div>
</div>

<!-- SMS Log -->
<div class="lsec">
    <div class="lhdr">
        <div class="lhtitle"><i class="fas fa-list-ul"></i> SMS Log</div>
        <div style="display:flex;align-items:center;gap:7px;">
            <span class="cpill"><?= number_format($totalRows) ?> records</span>
            <?php $days = (date_diff(date_create($filterFrom), date_create($filterTo))->days) + 1; ?>
            <span class="cpill"><?= $days ?> day<?= $days != 1 ? 's' : '' ?></span>
        </div>
    </div>

    <?php if (empty($logs)): ?>
    <div class="empty">
        <div class="eico"><i class="fas fa-comment-slash"></i></div>
        <h3>No SMS records</h3>
        <p><?= $smsLogsExists ? 'No messages in selected date range.' : 'Table auto-creates on first use.' ?></p>
    </div>
    <?php else: ?>
    <div class="tscr">
        <table class="lt">
            <thead><tr>
                <th style="width:32px;">#</th>
                <th>Date / Time</th>
                <th>Customer</th>
                <th>Loan</th>
                <th>Branch</th>
                <th>Event</th>
                <th>Phone</th>
                <th>Message</th>
                <th>Att.</th>
                <th>Status</th>
            </tr></thead>
            <tbody>
            <?php foreach ($logs as $i => $log):
                $fail = ($log['status'] === 'failed');
                $m    = evtMeta($log['event_type'] ?? null);
                $att  = (int)($log['attempt'] ?? 1);
            ?>
            <tr class="<?= $fail ? 'rf' : '' ?>">
                <td><span class="rn"><?= $offset + $i + 1 ?></span></td>
                <td>
                    <div class="tdate">
                        <?= $log['created_at'] ? date('j M Y', strtotime($log['created_at'])) : '—' ?>
                    </div>
                    <div class="ttime">
                        <?= $log['created_at'] ? date('H:i:s', strtotime($log['created_at'])) : '' ?>
                    </div>
                </td>
                <td>
                    <?php if (!empty($log['customer_name'])): ?>
                        <div class="tname-c">
                            <?= htmlspecialchars(ucwords(strtolower(trim($log['customer_name'])))) ?>
                        </div>
                        <div class="tid"><?= htmlspecialchars($log['national_id'] ?? '') ?></div>
                    <?php else: ?>
                        <span style="color:var(--t4);">—</span>
                    <?php endif; ?>
                </td>
                <td>
                    <?php if (!empty($log['full_loan_number'])): ?>
                        <div class="tloan"><?= htmlspecialchars($log['full_loan_number']) ?></div>
                    <?php elseif (!empty($log['loan_id_display'])): ?>
                        <div class="tloan"><?= htmlspecialchars($log['loan_id_display']) ?></div>
                    <?php elseif ($log['loan_id']): ?>
                        <div class="tloan">#<?= (int)$log['loan_id'] ?></div>
                    <?php else: ?>
                        <span style="color:var(--t4);">—</span>
                    <?php endif; ?>
                    <?php if (!empty($log['pawn_type'])): ?>
                        <span class="ttype"><?= loanTypeShort($log['pawn_type']) ?></span>
                    <?php endif; ?>
                </td>
                <td style="font-size:11.5px;color:var(--t2);">
                    <?= htmlspecialchars($log['branch_name'] ?? '—') ?>
                </td>
                <td>
                    <span class="epill" style="background:<?= $m[0] ?>;color:<?= $m[1] ?>;">
                        <i class="fas <?= $m[3] ?>" style="font-size:8px;"></i>
                        <?= evtLabel($log['event_type'] ?? null) ?>
                    </span>
                </td>
                <td>
                    <span class="ph"><?= htmlspecialchars(maskPhone($log['phone'] ?? '')) ?></span>
                </td>
                <td>
                    <?php if (!empty($log['message'])): ?>
                        <div class="mprev"
                             onclick="showMsg(this,'<?= htmlspecialchars(evtLabel($log['event_type'] ?? null), ENT_QUOTES) ?>')"
                             data-full="<?= htmlspecialchars($log['message']) ?>">
                            <?= htmlspecialchars(
                                mb_strlen($log['message']) > 50
                                    ? mb_substr($log['message'], 0, 50) . '…'
                                    : $log['message']
                            ) ?>
                        </div>
                    <?php else: ?>
                        <span style="color:var(--t4);">—</span>
                    <?php endif; ?>
                </td>
                <td>
                    <span class="ab <?= $att > 1 ? 'rt' : '' ?>">
                        <?= $att ?><?= $att > 1 ? '×' : '' ?>
                    </span>
                    <?php if (!empty($log['message_id'])): ?>
                        <div class="msgid"><?= htmlspecialchars(substr($log['message_id'], 0, 9)) ?>…</div>
                    <?php endif; ?>
                </td>
                <td>
                    <span class="spill <?= $fail ? 'sfail' : 'ssent' ?>">
                        <i class="fas <?= $fail ? 'fa-times' : 'fa-check' ?>" style="font-size:8px;"></i>
                        <?= $fail ? 'Failed' : 'Sent' ?>
                    </span>
                    <?php if (!empty($log['error'])): ?>
                        <span class="etxt" title="<?= htmlspecialchars($log['error']) ?>">
                            <?= htmlspecialchars(substr($log['error'], 0, 28)) ?>…
                        </span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <div class="pager">
        <div class="pinfo">
            Showing <?= number_format($offset + 1) ?>–<?= number_format(min($offset + $perPage, $totalRows)) ?>
            of <?= number_format($totalRows) ?>
        </div>
        <div class="plinks">
        <?php
        $base = '?from=' . urlencode($filterFrom) . '&to=' . urlencode($filterTo);
        echo '<a href="' . $base . '&page=' . ($filterPage - 1) . '" class="pgb ' . ($filterPage <= 1 ? 'off' : '') . '">
                <i class="fas fa-chevron-left" style="font-size:8px;"></i>
              </a>';
        $s = max(1, $filterPage - 2);
        $e = min($totalPages, $filterPage + 2);
        if ($s > 1) echo '<span class="pgb off" style="border:none;cursor:default;">…</span>';
        for ($p = $s; $p <= $e; $p++) {
            echo '<a href="' . $base . '&page=' . $p . '" class="pgb ' . ($p === $filterPage ? 'on' : '') . '">' . $p . '</a>';
        }
        if ($e < $totalPages) echo '<span class="pgb off" style="border:none;cursor:default;">…</span>';
        echo '<a href="' . $base . '&page=' . ($filterPage + 1) . '" class="pgb ' . ($filterPage >= $totalPages ? 'off' : '') . '">
                <i class="fas fa-chevron-right" style="font-size:8px;"></i>
              </a>';
        ?>
        </div>
    </div>
    <?php endif; ?>
</div>

</div><!-- /.content -->
</div><!-- /.main -->
</div><!-- /.layout -->

<!-- Message modal -->
<div id="mm">
    <div class="mbox">
        <div class="mhead">
            <div class="mhico"><i class="fas fa-comment-dots"></i></div>
            <div>
                <div class="mtitle">Full Message</div>
                <div class="msub" id="mevt">SMS Content</div>
            </div>
        </div>
        <div class="mbody" id="mbody"></div>
        <div class="mfoot">
            <button class="mclose" onclick="document.getElementById('mm').classList.remove('open')">
                <i class="fas fa-times" style="margin-right:4px;"></i>Close
            </button>
        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script>
// ── Hourly heatmap ──────────────────────────────────────────────────────────
(function () {
    const d  = <?= json_encode(array_values($hourlyData)) ?>;
    const mx = Math.max(...d, 1);
    const g  = document.getElementById('hmg');
    if (!g) return;
    d.forEach((v, h) => {
        const c = document.createElement('div');
        c.className   = 'hm';
        c.style.background = v > 0
            ? `rgba(212,160,23,${(0.12 + v / mx * 0.78).toFixed(2)})`
            : 'rgba(255,255,255,0.04)';
        c.title = `${String(h).padStart(2, '0')}:00 — ${v} message${v !== 1 ? 's' : ''}`;
        g.appendChild(c);
    });
})();

// ── 30-day volume chart ─────────────────────────────────────────────────────
(function () {
    const raw    = <?= json_encode($chartData) ?>;
    const labels = [], sent = [], failed = [];
    const today  = new Date();
    for (let i = 29; i >= 0; i--) {
        const d = new Date(today);
        d.setDate(d.getDate() - i);
        const k = d.toISOString().split('T')[0];
        labels.push(d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }));
        const f = raw.find(r => r.send_date === k);
        sent.push(f ? parseInt(f.sent_cnt || f.cnt) : 0);
        failed.push(f ? parseInt(f.fail_cnt || 0) : 0);
    }
    const c = document.getElementById('vc');
    if (!c) return;
    new Chart(c, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: 'Sent', data: sent,
                    borderColor: '#D4A017', backgroundColor: 'rgba(212,160,23,0.07)',
                    borderWidth: 2, pointBackgroundColor: '#D4A017',
                    pointRadius: 2.5, pointHoverRadius: 6,
                    fill: true, tension: 0.4, order: 1,
                },
                {
                    label: 'Failed', data: failed,
                    borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.05)',
                    borderWidth: 1.5, borderDash: [4, 3],
                    pointBackgroundColor: '#ef4444', pointRadius: 2, pointHoverRadius: 5,
                    fill: true, tension: 0.4, order: 2,
                },
            ],
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#0C1F0E', borderColor: 'rgba(212,160,23,.25)',
                    borderWidth: 1, titleColor: '#D4A017', bodyColor: '#9ca3af',
                    padding: 10,
                    callbacks: { label: ctx => ` ${ctx.dataset.label}: ${ctx.parsed.y}` },
                },
            },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,.025)' }, ticks: { color: '#374a38', font: { size: 9 }, maxRotation: 45, maxTicksLimit: 10 } },
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,.03)' }, ticks: { color: '#374a38', font: { size: 9 }, stepSize: 1 } },
            },
        },
    });
})();

// ── Event type doughnut ─────────────────────────────────────────────────────
(function () {
    const raw = <?= json_encode($typeBreakdown) ?>;
    if (!raw || !raw.length) return;
    const cm = {
        'loan.due_soon_3days': '#f59e0b', 'loan.due_today': '#ef4444',
        'loan.overdue': '#ec4899',        'loan.extended': '#8b5cf6',
        'loan.issued': '#3b82f6',         'loan.approved': '#10b981',
        'loan.disbursed': '#0d9488',      'loan.closed': '#64748b',
        'loan.drafted': '#0ea5e9',
    };
    const c = document.getElementById('tc');
    if (!c) return;
    new Chart(c, {
        type: 'doughnut',
        data: {
            labels: raw.map(d => d.event_type),
            datasets: [{
                data: raw.map(d => parseInt(d.cnt)),
                backgroundColor: raw.map(d => cm[d.event_type] || '#64748b'),
                borderWidth: 2, borderColor: '#162018',
                hoverBorderColor: 'rgba(212,160,23,.35)', hoverOffset: 4,
            }],
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '66%',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#0C1F0E', borderColor: 'rgba(212,160,23,.25)',
                    borderWidth: 1, titleColor: '#D4A017', bodyColor: '#9ca3af', padding: 9,
                    callbacks: {
                        title: ctx => [ctx[0].label.replace('loan.', '').replace(/_/g, ' ')],
                        label: ctx => ` ${ctx.parsed} sent`,
                    },
                },
            },
        },
    });
})();

// ── Message modal ───────────────────────────────────────────────────────────
function showMsg(el, evt) {
    document.getElementById('mbody').textContent = el.getAttribute('data-full') || el.textContent;
    document.getElementById('mevt').textContent  = evt || 'SMS Content';
    document.getElementById('mm').classList.add('open');
}
document.getElementById('mm').addEventListener('click', function (e) {
    if (e.target === this) this.classList.remove('open');
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.getElementById('mm').classList.remove('open');
});

// ── Count-up animation ──────────────────────────────────────────────────────
(function () {
    const el = document.getElementById('anim-tot');
    if (!el) return;
    const t = parseInt(el.textContent.replace(/,/g, ''));
    if (!t) return;
    let n = 0;
    const step = Math.ceil(t / 45);
    const iv = setInterval(() => {
        n = Math.min(n + step, t);
        el.textContent = n.toLocaleString();
        if (n >= t) clearInterval(iv);
    }, 28);
})();
</script>
</body>
</html>
