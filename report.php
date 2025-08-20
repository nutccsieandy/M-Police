<?php
// --- 用獨立的 Session 名稱，與警方系統隔離 ---
session_name('PUBSESSID');
$__sp = ini_get('session.save_path');
if (!$__sp || !is_dir($__sp) || !is_writable($__sp)) {
  $__alt = __DIR__.'/.pub_sessions';
  if (!is_dir($__alt)) { @mkdir($__alt, 0777, true); }
  if (is_dir($__alt) && is_writable($__alt)) { session_save_path($__alt); }
}
session_start();

// --- 小工具 ---
function e($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function errpage($title,$msg){
  http_response_code(500);
  echo "<!doctype html><meta charset='utf-8'><pre style='white-space:pre-wrap;color:#fff;background:#111;padding:12px;border-radius:8px'>"
     . e($title) . "\n\n" . e($msg) . "</pre>";
  exit;
}

// --- DB（只用 mysqli_*） ---
function db(){
  $host='127.0.0.1'; $user='root'; $pass=''; $dbname='svt'; $port=3306;
  $link = @mysqli_connect($host,$user,$pass,null,$port);
  if(!$link){ errpage('MySQL 連線失敗', mysqli_connect_error()); }
  @mysqli_set_charset($link,'utf8mb4');
  @mysqli_query($link,"CREATE DATABASE IF NOT EXISTS `$dbname` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
  mysqli_select_db($link,$dbname);
  @mysqli_query($link,"CREATE TABLE IF NOT EXISTS public_reports (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    reporter_name VARCHAR(64) NULL,
    reporter_phone VARCHAR(32) NULL,
    plate_no VARCHAR(20) NOT NULL,
    location VARCHAR(255) NULL,
    note TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
  return $link;
}
function q($db,$sql){ $res=@mysqli_query($db,$sql); if($res===false){ errpage('SQL 執行失敗', mysqli_error($db)."\n\n".$sql); } return $res; }
function esc($db,$s){ return mysqli_real_escape_string($db,(string)$s); }

$db = db();

// PRG 流程：處理提交
if($_SERVER['REQUEST_METHOD']==='POST'){
  $name  = esc($db, trim($_POST['reporter_name']  ?? ''));
  $phone = esc($db, trim($_POST['reporter_phone'] ?? ''));
  $plate_raw = trim($_POST['plate_no'] ?? '');
  $loc   = esc($db, trim($_POST['location'] ?? ''));
  $note  = esc($db, trim($_POST['note'] ?? ''));

  if($plate_raw!==''){
    $plate = esc($db,$plate_raw);
    q($db,"INSERT INTO public_reports(reporter_name,reporter_phone,plate_no,location,note)
           VALUES('$name','$phone','$plate','$loc','$note')");
    $id  = mysqli_insert_id($db);
    $ref = 'RP'.date('ymd').'-'.str_pad((string)$id,6,'0',STR_PAD_LEFT); // 申報編號
    $_SESSION['flash_ok'] = "申報成功！您的回報編號：{$ref}";
  } else {
    $_SESSION['flash_err'] = '請填寫車牌';
  }
  header('Location: report.php'); exit;
}

// RWD 樣式
$css = <<<CSS
:root{--bg:#0b1020;--card:#111827;--muted:#6b7280;--text:#e5e7eb;--pri:#2563eb;--pri-2:#1f2937}
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:#e5e7eb;margin:0}
.nav{display:flex;align-items:center;justify-content:center;background:#0f172a;padding:12px 14px}
.brand{font-weight:700;color:#93c5fd}
.container{max-width:900px;margin:22px auto;padding:0 16px}
.card{background:var(--card);border:1px solid #273244;border-radius:14px;padding:16px}
label{display:block;margin-top:8px;color:#cbd5e1;font-size:14px}
input,textarea{width:100%;padding:10px;margin-top:6px;background:#0f172a;border:1px solid #374151;color:#e5e7eb;border-radius:10px}
.btn{display:inline-flex;align-items:center;gap:6px;background:var(--pri-2);color:#fff;text-decoration:none;border:1px solid #2b3444;border-radius:10px;padding:10px 14px;cursor:pointer}
.flash{padding:10px 14px;border-radius:10px;margin:12px 0}
.flash.ok{background:#0f2f26;color:#a7f3d0;border:1px solid #1b4d3f}
.flash.err{background:#3f1d1d;color:#fecaca;border:1px solid #5b2727}
.notice{color:#9ca3af;font-size:13px;margin-top:8px}
CSS;

$flash = '';
if(!empty($_SESSION['flash_ok'])){ $flash = "<div class='flash ok'>".e($_SESSION['flash_ok'])."</div>"; unset($_SESSION['flash_ok']); }
elseif(!empty($_SESSION['flash_err'])){ $flash = "<div class='flash err'>".e($_SESSION['flash_err'])."</div>"; unset($_SESSION['flash_err']); }

// HTML
echo <<<HTML
<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<link rel="icon" href="images/MP.png" type="image/x-icon" / >
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>民眾回報（獨立）</title>
<link rel="icon" href="data:,">
<style>$css</style>
</head>
<body>
  <div class="nav"><div class="brand"><p style="font-size:25px;">M-Police 民眾回報資訊系統</p></div></div>
  <div class="container">
    <div class="card">
      <h2>民眾回報表單</h2>
      $flash
      <form method="post" novalidate>
        <label>您的姓名（可留空）<input name="reporter_name"></label>
        <label>聯絡電話（可留空）<input name="reporter_phone"></label>
        <label>車牌（必填）<input name="plate_no" required></label>
        <label>地點（可留空）<input name="location"></label>
        <label>備註（可留空）<textarea name="note" rows="4"></textarea></label>
        <button class="btn" type="submit">送出</button>
      </form>
      <div class="notice">此頁面僅供民眾通報使用；為警方公開之E化資訊系統。</div>
    </div>
  </div>
</body>
</html>
HTML;
