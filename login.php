<?php 
// --- Session 儲存路徑（避免 Windows 權限問題） ---
$__sp = ini_get('session.save_path');
if (!$__sp || !is_dir($__sp) || !is_writable($__sp)) {
  $__alt = __DIR__ . '/.sessions';
  if (!is_dir($__alt)) { @mkdir($__alt, 0777, true); }
  if (is_dir($__alt) && is_writable($__alt)) { session_save_path($__alt); }
}
session_name('MPSESSID');
session_start();

// --- 小工具 ---
function e($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function errpage($title,$msg){
  http_response_code(500);
  echo "<!doctype html><meta charset=\"utf-8\"><pre style=\"white-space:pre-wrap;color:#fff;background:#111;padding:12px;border-radius:8px\">"
      . e($title) . "\n\n" . e($msg) . "</pre>";
  exit;
}

// --- DB（只用 mysqli_*）---
function db(){
  $host='127.0.0.1'; $user='root'; $pass=''; $dbname='svt'; $port=3306;
  $link = @mysqli_connect($host,$user,$pass,null,$port);
  if(!$link){ errpage('無法連線 MySQL', mysqli_connect_error()); }
  @mysqli_set_charset($link,'utf8mb4');
  @mysqli_query($link,"CREATE DATABASE IF NOT EXISTS `$dbname` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
  mysqli_select_db($link, $dbname);

  // schema
  @mysqli_query($link,"CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','officer') NOT NULL DEFAULT 'officer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  @mysqli_query($link,"CREATE TABLE IF NOT EXISTS blacklist (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    plate_no VARCHAR(20) NOT NULL,
    reason VARCHAR(255) NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uix_plate (plate_no)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  @mysqli_query($link,"CREATE TABLE IF NOT EXISTS detections (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    image_mime VARCHAR(64) NULL,
    image_blob LONGBLOB NULL,
    plate_text VARCHAR(32) NULL,
    is_blacklisted TINYINT(1) NOT NULL DEFAULT 0,
    matched_blacklist_id BIGINT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_plate (plate_text)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  @mysqli_query($link,"CREATE TABLE IF NOT EXISTS public_reports (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    reporter_name VARCHAR(64) NULL,
    reporter_phone VARCHAR(32) NULL,
    plate_no VARCHAR(20) NOT NULL,
    location VARCHAR(255) NULL,
    note TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_rplate (plate_no)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  return $link;
}
function q($db,$sql){ $res=@mysqli_query($db,$sql); if($res===false) errpage('SQL 執行失敗', mysqli_error($db)."\n\n".$sql); return $res; }
function esc($db,$s){ return mysqli_real_escape_string($db,(string)$s); }

// --- 預設管理者 ---
function ensure_default_admin($db){
  $r = q($db,"SELECT COUNT(*) c FROM users");
  $row = mysqli_fetch_assoc($r);
  if((int)$row['c']===0){
    $hash = password_hash('admin123', PASSWORD_BCRYPT);
    $u = esc($db,'admin'); $h = esc($db,$hash);
    q($db,"INSERT INTO users(username,password_hash,role) VALUES('$u','$h','admin')");
  }
}

// --- 主流程 ---
$db = db();
ensure_default_admin($db);

// 若已登入，依角色直接導向
if (!empty($_SESSION['user']) && isset($_SESSION['user']['role'])) {
  if ($_SESSION['user']['role'] === 'admin') {
    header('Location: console.php'); exit;
  } else {
    header('Location: officer.php'); exit;
  }
}

// 安全地先定義 $msg
$msg = '';

// 登入提交
if($_SERVER['REQUEST_METHOD'] === 'POST'){
  $username = isset($_POST['username']) ? trim($_POST['username']) : '';
  $password = isset($_POST['password']) ? (string)$_POST['password'] : '';
  $u = esc($db,$username);
  $r = q($db,"SELECT id,username,password_hash,role FROM users WHERE username='$u' LIMIT 1");
  $row = mysqli_fetch_assoc($r);
  if($row && password_verify($password, $row['password_hash'])){
    $_SESSION['user'] = ['id'=>$row['id'], 'username'=>$row['username'], 'role'=>$row['role']];
    // 依角色分流：admin→後台；officer→前台
    if ($row['role'] === 'admin') {
      header('Location: console.php');
    } else {
      header('Location: officer.php');
    }
    exit;
  } else {
    $msg = '帳號或密碼錯誤';
  }
}

// --- RWD CSS（間距更大、模塊更大） ---
$css = <<<CSS
:root{
  --bg:#0b1020; --card:#111827; --muted:#94a3b8; --text:#e5e7eb;
  --pri:#2563eb; --pri-2:#1f2937;
}
*{box-sizing:border-box}
body{
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  background:var(--bg); color:var(--text); margin:0;
}
.nav{
  display:flex; gap:12px; flex-wrap:wrap; align-items:center; justify-content:center;
  background:#0f172a; padding:20px 24px; border-bottom:1px solid #1f2937;
}
.nav .brand{font-weight:800; font-size:22px; margin-right:auto; color:#93c5fd}
.nav a,.btn{
  display:inline-flex; align-items:center; gap:8px;
  background:var(--pri-2); color:#fff; text-decoration:none;
  border:1px solid #2b3444; border-radius:16px;
  padding:14px 18px; cursor:pointer; font-size:16px;
}
.container{
  max-width:1280px; margin:56px auto; padding:0 20px; display:grid; gap:28px;
}
.card{
  background:var(--card); border:1px solid #273244; border-radius:22px;
  padding:32px 36px; box-shadow:0 12px 28px rgba(0,0,0,.35);
}
h2{font-size:28px; margin:0 0 18px}
label{display:block; margin-top:16px; color:#cbd5e1; font-size:16px}
input{
  width:100%; padding:16px; margin-top:10px; font-size:16px;
  background:#0f172a; border:1px solid #374151; color:#e5e7eb; border-radius:14px
}
button.btn{font-size:16px; padding:14px 18px; margin-top:16px}
.flash{padding:12px 14px; border-radius:14px; margin-bottom:14px; font-size:15px}
.flash.err{background:#3f1d1d; color:#fecaca; border:1px solid #5b2727}
.footer{color:var(--muted); font-size:13px; text-align:center; margin:16px 0}
@media (max-width:720px){
  .container{margin:32px auto; padding:0 16px; gap:20px}
  .card{padding:24px}
  h2{font-size:24px}
  .nav{padding:16px}
  .nav .brand{font-size:20px}
}
CSS;

// --- 動態訊息 ---
$flash = $msg !== '' ? ('<div class="flash err">'.e($msg).'</div>') : '';

// --- 輸出 ---
echo <<<HTML
<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登入</title>
<link rel="icon" href="data:,">
<style>$css</style>
</head>
<body>
  <div class="nav">
    <div class="brand">M-Police 資訊系統</div>
  </div>
  <div class="container">
    <div class="card" style="max-width:820px;margin:0 auto;">
      <h2>登入系統</h2>
      $flash
      <form method="post" autocomplete="off">
        <label>帳號<input name="username" required></label>
        <label>密碼<input type="password" name="password" required></label>
        <button class="btn" type="submit">登入</button>
      </form>
      <div class="footer">請依據使用情境輸入屬性不同之帳號</div>
    </div>
  </div>
</body>
</html>
HTML;
