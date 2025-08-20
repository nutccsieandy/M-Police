<?php
// === Session ===
session_name('MPSESSID');
$__sp = ini_get('session.save_path');
if (!$__sp || !is_dir($__sp) || !is_writable($__sp)) {
  $__alt = __DIR__.'/.sessions';
  if (!is_dir($__alt)) { @mkdir($__alt, 0777, true); }
  if (is_dir($__alt) && is_writable($__alt)) { session_save_path($__alt); }
}
session_start();

// === 工具 ===
function e($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function errpage($t,$m){ http_response_code(500); echo "<!doctype html><meta charset='utf-8'><pre style='white-space:pre-wrap;color:#fff;background:#111;padding:12px;border-radius:8px'>".e($t)."\n\n".e($m)."</pre>"; exit; }

// === 僅允許 officer ===
if (empty($_SESSION['user'])) { header('Location: login.php'); exit; }
$user = $_SESSION['user'];
if ($user['role'] !== 'officer') {
  // admin 或其他角色一律導回後台
  $_SESSION['flash_err'] = '僅外勤人員可進入此頁';
  header('Location: console.php'); exit;
}

// === DB (mysqli_*) ===
function db(){
  $l=@mysqli_connect('127.0.0.1','root','',null,3306);
  if(!$l) errpage('MySQL 連線失敗', mysqli_connect_error());
  @mysqli_set_charset($l,'utf8mb4');
  @mysqli_query($l,"CREATE DATABASE IF NOT EXISTS `svt` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
  mysqli_select_db($l,'svt');

  // schema（沿用既有表）
  @mysqli_query($l,"CREATE TABLE IF NOT EXISTS users(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','officer') NOT NULL DEFAULT 'officer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  @mysqli_query($l,"CREATE TABLE IF NOT EXISTS blacklist(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    plate_no VARCHAR(20) NOT NULL,
    reason VARCHAR(255) NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uix_plate(plate_no)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  @mysqli_query($l,"CREATE TABLE IF NOT EXISTS detections(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    image_mime VARCHAR(64) NULL,
    image_blob LONGBLOB NULL,
    plate_text VARCHAR(32) NULL,
    is_blacklisted TINYINT(1) NOT NULL DEFAULT 0,
    matched_blacklist_id BIGINT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_plate(plate_text)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  @mysqli_query($l,"CREATE TABLE IF NOT EXISTS public_reports(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    reporter_name VARCHAR(64) NULL,
    reporter_phone VARCHAR(32) NULL,
    plate_no VARCHAR(20) NOT NULL,
    location VARCHAR(255) NULL,
    note TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_rplate(plate_no)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  return $l;
}
function q($db,$sql){ $r=@mysqli_query($db,$sql); if($r===false) errpage('SQL 失敗', mysqli_error($db)."\n\n".$sql); return $r; }
function esc($db,$s){ return mysqli_real_escape_string($db,(string)$s); }

$db = db();

// === 影像輸出（縮圖/原圖）===
if (isset($_GET['img'])) {
  $id=(int)$_GET['img'];
  $r=q($db,"SELECT image_mime,image_blob FROM detections WHERE id=$id");
  if($row=mysqli_fetch_assoc($r)){
    header("Content-Type: ".($row['image_mime']?:'application/octet-stream'));
    echo $row['image_blob']; exit;
  }
  http_response_code(404); exit('not found');
}

// === flash 訊息 ===
$flash_ok = ''; $flash_err = '';

// === 1) 手動查詢（可選擇寫入紀錄）===
if ($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['act']??'')==='manual_check') {
  $plate_raw = trim($_POST['plate_no'] ?? '');
  $save_log  = isset($_POST['save_log']) ? 1 : 0;
  if ($plate_raw===''){
    $flash_err = '請輸入車牌再查詢';
  } else {
    $plate = esc($db, $plate_raw);
    $r = q($db,"SELECT id,reason FROM blacklist WHERE plate_no='$plate' AND is_active=1 LIMIT 1");
    if($bl = mysqli_fetch_assoc($r)){
      $flash_ok = "盤點結果：<b>".e($plate_raw)."</b> 命中黑名單（原因：".e($bl['reason'])."）";
      if ($save_log){
        q($db,"INSERT INTO detections(plate_text,is_blacklisted,matched_blacklist_id) VALUES('$plate',1,".(int)$bl['id'].")");
      }
    } else {
      $flash_ok = "盤點結果：<b>".e($plate_raw)."</b> 未命中黑名單";
      if ($save_log){
        q($db,"INSERT INTO detections(plate_text,is_blacklisted,matched_blacklist_id) VALUES('$plate',0,NULL)");
      }
    }
  }
}

// === 2) 圖片上傳（之後於列表填入車牌 → 即時比對）===
if ($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['act']??'')==='upload_img' && isset($_FILES['image'])) {
  $img=$_FILES['image'];
  if($img['error']===UPLOAD_ERR_OK){
    $ext=strtolower(pathinfo($img['name'],PATHINFO_EXTENSION));
    if(in_array($ext,['jpg','jpeg','png','webp'])){
      $fi=function_exists('finfo_open')?finfo_open(FILEINFO_MIME_TYPE):null;
      $mime=$fi?finfo_file($fi,$img['tmp_name']):'application/octet-stream';
      if($fi)finfo_close($fi);
      $blob=file_get_contents($img['tmp_name']);
      $mime_esc=esc($db,$mime);
      $blob_esc=esc($db,$blob);
      q($db,"INSERT INTO detections(image_mime,image_blob) VALUES('$mime_esc','$blob_esc')");
      $flash_ok = '圖片已上傳，請在下方列表填入車牌完成盤點。';
    } else {
      $flash_err = '僅支援 jpg / jpeg / png / webp 檔案';
    }
  } else {
    $flash_err = '上傳失敗（錯誤代碼 '.$img['error'].'）';
  }
}

// === 圖片紀錄行內更新：輸入車牌→即時比對黑名單 ===
if ($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['act']??'')==='det_update') {
  $id=(int)($_POST['id']??0);
  $plate_raw=trim($_POST['plate_text']??'');
  if ($id<=0){ $flash_err='ID 無效'; }
  else {
    if($plate_raw!==''){
      $plate=esc($db,$plate_raw);
      $hit=0; $bid='NULL';
      $r=q($db,"SELECT id FROM blacklist WHERE plate_no='$plate' AND is_active=1 LIMIT 1");
      if($row=mysqli_fetch_assoc($r)){ $hit=1; $bid=(int)$row['id']; }
      q($db,"UPDATE detections SET plate_text='$plate', is_blacklisted=$hit, matched_blacklist_id=$bid WHERE id=$id");
      $flash_ok = ($hit? '命中黑名單！':'已更新車牌，未命中黑名單。');
    }else{
      q($db,"UPDATE detections SET plate_text=NULL, is_blacklisted=0, matched_blacklist_id=NULL WHERE id=$id");
      $flash_ok = '已清空該筆的車牌';
    }
  }
}

// === 查詢/篩選（列表）===
$q = trim($_GET['q'] ?? '');
$only_hit = isset($_GET['only_hit']) ? 1 : 0;
$where = [];
if ($q!==''){
  $like = esc($db,"%$q%");
  $where[] = "(plate_text LIKE '$like')";
}
if ($only_hit){ $where[] = "is_blacklisted=1"; }
$wsql = $where ? ("WHERE ".implode(" AND ",$where)) : "";
$det = q($db,"SELECT id,image_mime,plate_text,is_blacklisted,matched_blacklist_id,created_at FROM detections $wsql ORDER BY id DESC LIMIT 200");

// === RWD / UI ===
$css=<<<CSS
:root{--bg:#0b1020;--card:#111827;--muted:#9ca3af;--text:#e5e7eb;--pri:#2563eb;--pri-2:#1f2937}
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);margin:0}
.nav{position:sticky;top:0;z-index:20;display:flex;gap:12px;flex-wrap:wrap;align-items:center;background:#0f172a;padding:16px 18px;border-bottom:1px solid #1f2937}
.brand{font-weight:800;font-size:20px;margin-right:auto;color:#93c5fd}
.nav .right{margin-left:auto;display:flex;gap:8px}
.nav a,.btn{display:inline-flex;align-items:center;gap:6px;background:var(--pri-2);color:#fff;text-decoration:none;border:1px solid #2b3444;border-radius:12px;padding:10px 14px;cursor:pointer}
.container{max-width:1200px;margin:26px auto;padding:0 14px;display:grid;gap:18px}
.card{background:var(--card);border:1px solid #273244;border-radius:16px;padding:18px}
.hgrid{display:grid;gap:14px;grid-template-columns:repeat(2,minmax(0,1fr))}
@media (max-width:900px){ .hgrid{grid-template-columns:1fr} }
label{display:block;margin-top:8px;color:#cbd5e1;font-size:14px}
.ipt,.sel,textarea{width:100%;padding:12px;margin-top:6px;background:#0f172a;border:1px solid #374151;color:#e5e7eb;border-radius:10px}
.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid #223047;padding:10px;text-align:left;vertical-align:top}
.table th{background:#0f172a}
.thumb{height:60px;border-radius:8px}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #2b3444;background:#0f172a;color:#cbd5e1;font-size:12px}
.tag.hit{background:#113022;color:#86efac;border-color:#164a3a}
.flash{padding:8px 12px;border-radius:10px;margin:8px 0}
.flash.ok{background:#0f2f26;color:#a7f3d0;border:1px solid #1b4d3f}
.flash.err{background:#3f1d1d;color:#fecaca;border:1px solid #5b2727}
.inline{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
CSS;

$uName=e($user['username']); $uRole=e($user['role']);
$flashHtml = '';
if($flash_ok!=='') $flashHtml .= "<div class='flash ok'>{$flash_ok}</div>";
if($flash_err!=='') $flashHtml .= "<div class='flash err'>{$flash_err}</div>";

// 列表 rows
$rows='';
while($r=mysqli_fetch_assoc($det)){
  $id=(int)$r['id'];
  $src = ($r['image_mime'] && $r['image_mime']!=='') ? "<span class='tag'>圖片</span>" : "<span class='tag'>手動</span>";
  $hit = ((int)$r['is_blacklisted']===1) ? "<span class='tag hit'>命中</span>" : "<span class='tag'>—</span>";
  $thumb = ($r['image_mime'] && $r['image_mime']!=='') ? "<img class='thumb' src='officer.php?img=$id' alt='img'>" : '—';
  $plate_val = e($r['plate_text']);
  $created = e($r['created_at']);
  $rows .= "<tr>
    <td>$id</td>
    <td>$src</td>
    <td>$thumb</td>
    <td>
      <form method='post' class='inline'>
        <input type='hidden' name='act' value='det_update'>
        <input type='hidden' name='id' value='$id'>
        <input class='ipt' name='plate_text' placeholder='輸入車牌後存檔比對' value='$plate_val' style='max-width:220px'>
        <button class='btn btn-mini' type='submit'>存</button>
      </form>
    </td>
    <td>$hit</td>
    <td>$created</td>
  </tr>";
}

// 查詢欄位值
$qHtml = e($q);
$chkOnly = $only_hit ? 'checked' : '';

// === 輸出 ===
echo <<<HTML
<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MPolice 外勤系統</title>
<link rel="icon" href="data:,"><style>$css</style>
</head>
<body>
  <div class="nav">
    <div class="brand">M-Police 外勤系統</div>
    <div class="right">
      <a class="btn" href="officer.php?logout=1" onclick="event.preventDefault(); location.href='console.php?logout=1';">
  登出（{$uName} / {$uRole}）
</a>
    </div>
  </div>

  <div class="container">
    $flashHtml

    <div class="hgrid">
      <!-- 手動查詢 -->
      <div class="card">
        <h3>手動輸入車牌盤點</h3>
        <form method="post" class="inline" style="margin-top:6px">
          <input type="hidden" name="act" value="manual_check">
          <input class="ipt" name="plate_no" placeholder="例如 ABC-1234" required style="max-width:260px">
          <label class="inline" style="gap:6px"><input type="checkbox" name="save_log" value="1"> 同時寫入偵測紀錄</label>
          <button class="btn" type="submit">查詢</button>
        </form>
        <div style="color:#9ca3af;margin-top:8px">說明：勾選「寫入偵測紀錄」會把本次查詢存入 <code>detections</code>（無圖片）。</div>
      </div>

      <!-- 圖片上傳 -->
      <div class="card">
        <h3>圖片偵測（先上傳 → 下方列表填車牌比對）</h3>
        <form method="post" enctype="multipart/form-data" class="inline" style="margin-top:6px">
          <input type="hidden" name="act" value="upload_img">
          <input type="file" name="image" accept=".jpg,.jpeg,.png,.webp" class="ipt" required>
          <button class="btn" type="submit">上傳圖片</button>
        </form>
        <div style="color:#9ca3af;margin-top:8px">上傳後請到下方「最新紀錄」對該列輸入車牌並存檔，即可盤點是否命中黑名單。</div>
      </div>
    </div>

    <!-- 查詢/篩選 + 最新紀錄列表 -->
    <div class="card">
      <h3>最新紀錄（手動＋圖片）</h3>
      <form method="get" class="inline" style="margin-top:6px">
        <input class="ipt" name="q" value="{$qHtml}" placeholder="依車牌模糊查詢（例如 123 或 ABC）" style="max-width:260px">
        <label class="inline" style="gap:6px"><input type="checkbox" name="only_hit" value="1" $chkOnly> 只看命中黑名單</label>
        <button class="btn" type="submit">篩選</button>
        <a class="btn" href="officer.php">清除</a>
      </form>

      <div style="overflow:auto;margin-top:12px">
        <table class="table">
          <thead>
            <tr>
              <th>ID</th><th>來源</th><th>圖片</th><th>車牌（可編輯）</th><th>黑名單</th><th>時間</th>
            </tr>
          </thead>
          <tbody>$rows</tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>
HTML;
