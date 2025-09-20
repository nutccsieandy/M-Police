<?php
require_once __DIR__.'/config.php';
?>



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

// === 小工具 ===
function e($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
function errpage($t,$m){ http_response_code(500); echo "<!doctype html><meta charset='utf-8'><pre style='white-space:pre-wrap;color:#fff;background:#111;padding:12px;border-radius:8px'>".e($t)."\n\n".e($m)."</pre>"; exit; }
function gen_pw(){ // 統一臨時密碼產生器
  if (function_exists('random_bytes')) return bin2hex(random_bytes(4));
  return substr(str_shuffle('ABCDEFGHJKLMNPQRSTUVWXYZ23456789'), 0, 8);
}

// === 權限 ===
if (empty($_SESSION['user'])) { header('Location: login.php'); exit; }
$user = $_SESSION['user'];

// === DB (mysqli_*) ===
function db(){
  $l=@mysqli_connect('127.0.0.1','root','',null,3306);
  if(!$l) errpage('MySQL 連線失敗', mysqli_connect_error());
  @mysqli_set_charset($l,'utf8mb4');
  @mysqli_query($l,"CREATE DATABASE IF NOT EXISTS `svt` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
  mysqli_select_db($l,'svt');

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

// === 導覽動作 ===
if (isset($_GET['logout'])) { $_SESSION=[]; session_destroy(); header('Location: login.php'); exit; }

// === 圖片輸出（事件匯總預覽用）===
if (isset($_GET['img'])) {
  $id=(int)$_GET['img'];
  $r=q($db,"SELECT image_mime,image_blob FROM detections WHERE id=$id");
  if($row=mysqli_fetch_assoc($r)){
    header("Content-Type: ".($row['image_mime']?:'application/octet-stream'));
    echo $row['image_blob']; exit;
  }
  http_response_code(404); exit('not found');
}

/* =========================
   使用者：自助修改自己密碼（不限角色）
   act=self_pw（oldpw,newpw,newpw2）
   ========================= */
if ($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['act']??'')==='self_pw') {
  $old = (string)($_POST['oldpw'] ?? '');
  $np1 = (string)($_POST['newpw'] ?? '');
  $np2 = (string)($_POST['newpw2'] ?? '');
  if ($np1 === '' || strlen($np1) < 6) { $_SESSION['flash_err']='新密碼至少 6 碼'; header('Location: console.php#account'); exit; }
  if ($np1 !== $np2) { $_SESSION['flash_err']='兩次新密碼不一致'; header('Location: console.php#account'); exit; }

  $meId = (int)$user['id'];
  $rs = q($db,"SELECT password_hash FROM users WHERE id=$meId");
  $row = mysqli_fetch_assoc($rs);
  if (!$row || !password_verify($old, $row['password_hash'])) {
    $_SESSION['flash_err']='舊密碼不正確'; header('Location: console.php#account'); exit;
  }
  $hash = esc($db, password_hash($np1, PASSWORD_BCRYPT));
  q($db,"UPDATE users SET password_hash='$hash' WHERE id=$meId");
  $_SESSION['flash_ok']='已更新密碼'; header('Location: console.php#account'); exit;
}

// === 黑名單：新增/停啟（admin）===
if ($_SERVER['REQUEST_METHOD']==='POST' && in_array($_POST['act']??'', ['bl_add','bl_toggle','bl_quick_add'], true)) {
  if($user['role']!=='admin'){ $_SESSION['flash_err']='僅管理員可操作黑名單'; header('Location: console.php#blacklist'); exit; }
  if($_POST['act']==='bl_add' || $_POST['act']==='bl_quick_add'){
    $plate=esc($db,trim($_POST['plate_no']??'')); $reason=esc($db,trim($_POST['reason']??''));
    if($plate!=='') q($db,"INSERT INTO blacklist(plate_no,reason,is_active) VALUES('$plate','$reason',1) ON DUPLICATE KEY UPDATE reason=VALUES(reason),is_active=1");
  }else{
    $id=(int)($_POST['id']??0); $state=(int)($_POST['state']??0);
    q($db,"UPDATE blacklist SET is_active=$state WHERE id=$id");
  }
  header('Location: console.php#blacklist'); exit;
}

// === 使用者管理（admin）===
if ($_SERVER['REQUEST_METHOD']==='POST' && in_array($_POST['act']??'', ['u_role','u_reset','u_delete','u_import','u_setpw'], true)) {
  if($user['role']!=='admin'){ $_SESSION['flash_err']='僅管理員可管理帳號'; header('Location: console.php#users'); exit; }

  if($_POST['act']==='u_role'){
    $id=(int)($_POST['id']??0); $role=$_POST['role']==='admin'?'admin':'officer';
    if($role==='officer'){
      $rc=q($db,"SELECT COUNT(*) c FROM users WHERE role='admin'"); $c=(int)(mysqli_fetch_assoc($rc)['c']??0);
      $chk=q($db,"SELECT role FROM users WHERE id=$id"); $row=mysqli_fetch_assoc($chk);
      if(($row['role']??'')==='admin' && $c<=1){ $_SESSION['flash_err']='至少需保留一位管理員'; header('Location: console.php#users'); exit; }
    }
    q($db,"UPDATE users SET role='".esc($db,$role)."' WHERE id=$id");

  }elseif($_POST['act']==='u_reset'){
    $id=(int)($_POST['id']??0);
    $pw = gen_pw();
    $hash = esc($db, password_hash($pw, PASSWORD_BCRYPT));
    q($db,"UPDATE users SET password_hash='$hash' WHERE id=$id");
    $_SESSION['flash_ok']="已重設密碼：$pw";

  }elseif($_POST['act']==='u_setpw'){ // 直接指定使用者新密碼
    $id=(int)($_POST['id']??0);
    $np1 = (string)($_POST['newpw'] ?? '');
    $np2 = (string)($_POST['newpw2'] ?? '');
    if ($np1 === '' || strlen($np1) < 6) { $_SESSION['flash_err']='新密碼至少 6 碼'; header('Location: console.php#users'); exit; }
    if ($np1 !== $np2) { $_SESSION['flash_err']='兩次新密碼不一致'; header('Location: console.php#users'); exit; }
    $hash = esc($db, password_hash($np1, PASSWORD_BCRYPT));
    q($db,"UPDATE users SET password_hash='$hash' WHERE id=$id");
    $_SESSION['flash_ok']="已為使用者 #$id 設置新密碼";

  }elseif($_POST['act']==='u_delete'){
    $id=(int)($_POST['id']??0);
    if($id===$user['id']){ $_SESSION['flash_err']='不可刪除自己'; header('Location: console.php#users'); exit; }
    $chk=q($db,"SELECT role FROM users WHERE id=$id"); $row=mysqli_fetch_assoc($chk);
    if(($row['role']??'')==='admin'){
      $rc=q($db,"SELECT COUNT(*) c FROM users WHERE role='admin'"); $c=(int)(mysqli_fetch_assoc($rc)['c']??0);
      if($c<=1){ $_SESSION['flash_err']='至少需保留一位管理員'; header('Location: console.php#users'); exit; }
    }
    q($db,"DELETE FROM users WHERE id=$id");

  }elseif($_POST['act']==='u_import'){
    $raw='';
    if (!empty($_FILES['csvfile']['tmp_name']) && is_uploaded_file($_FILES['csvfile']['tmp_name'])) {
      $raw = file_get_contents($_FILES['csvfile']['tmp_name']);
    } else {
      $raw = (string)($_POST['csv'] ?? '');
    }
    $raw=trim($raw); $results=[];
    if($raw!==''){
      $lines=preg_split('/\r\n|\r|\n/',$raw);
      foreach($lines as $i=>$line){
        if(trim($line)==='') continue;
        $cols=str_getcsv($line); if(count($cols)<2){ $cols=preg_split('/\t+/', $line); }
        $u_raw=trim($cols[0]??''); $r_raw=trim($cols[1]??''); $p_raw=trim($cols[2]??'');
        if($i===0 && (mb_stripos($u_raw,'user')!==false || mb_stripos($u_raw,'帳號')!==false)) continue;
        if($u_raw==='') continue;

        $role = (in_array(mb_strtolower($r_raw,'UTF-8'),['admin','管理員'],true)?'admin':'officer');
        $username=esc($db,$u_raw); $role_esc=esc($db,$role);

        $exist=q($db,"SELECT id FROM users WHERE username='$username' LIMIT 1");
        if($row=mysqli_fetch_assoc($exist)){
          // 已存在 → 只更新角色
          q($db,"UPDATE users SET role='$role_esc' WHERE id=".(int)$row['id']);
          $results[] = [$u_raw,$role,'已存在→角色更新','—'];
        }else{
          // 新增帳號 → 有第三欄密碼就用，否則自動產生
          $pw = ($p_raw!=='') ? $p_raw : gen_pw();
          $hash = esc($db, password_hash($pw, PASSWORD_BCRYPT));
          q($db,"INSERT INTO users(username,password_hash,role) VALUES('$username','$hash','$role_esc')");
          $results[] = [$u_raw,$role, ($p_raw!==''?'新增成功（採用提供密碼）':'新增成功'), $pw];
        }
      }
    }
    $_SESSION['import_results']=$results;
  }
  header('Location: console.php#users'); exit;
}

// === 黑名單資料列 ===
$bl=q($db,"SELECT * FROM blacklist ORDER BY id DESC LIMIT 500");
$blRows='';
while($r=mysqli_fetch_assoc($bl)){
  $id=(int)$r['id']; $plate=e($r['plate_no']); $reason=e($r['reason']); $active=((int)$r['is_active']===1);
  $stateBtn=$active?'停用':'啟用'; $next=$active?0:1; $status=$active?'啟用':'停用';
  $op="<form method='post' style='display:inline'><input type='hidden' name='act' value='bl_toggle'><input type='hidden' name='id' value='$id'><input type='hidden' name='state' value='$next'><button class='btn' type='submit'>$stateBtn</button></form>";
  $blRows.="<tr><td>$id</td><td>$plate</td><td>$reason</td><td>$status</td><td>$op</td></tr>";
}

// === 事件匯總（民眾＋外勤） ===
$qinc = trim($_GET['qinc'] ?? '');
$onlyHit = isset($_GET['only_hit']) ? 1 : 0;
$qincLike = $qinc!=='' ? esc($db,"%$qinc%") : null;
$hitCond = $onlyHit ? "WHERE hit = 1" : "";
$plateCondDet = $qincLike ? "WHERE d.plate_text LIKE '$qincLike'" : "";
$plateCondRep = $qincLike ? "WHERE r.plate_no LIKE '$qincLike'" : "";
$sqlInc = "
SELECT * FROM (
  SELECT '外勤偵測' AS src, d.id AS src_id, d.plate_text AS plate, d.created_at,
         CASE WHEN bl.id IS NULL THEN 0 ELSE 1 END AS hit,
         bl.id AS bl_id, bl.reason AS bl_reason,
         d.id AS image_id, NULL AS reporter_name, NULL AS reporter_phone, NULL AS location, NULL AS note
  FROM detections d
  LEFT JOIN blacklist bl ON bl.plate_no = d.plate_text AND bl.is_active=1
  $plateCondDet
  UNION ALL
  SELECT '民眾舉報' AS src, r.id AS src_id, r.plate_no AS plate, r.created_at,
         CASE WHEN bl2.id IS NULL THEN 0 ELSE 1 END AS hit,
         bl2.id AS bl_id, bl2.reason AS bl_reason,
         NULL AS image_id, r.reporter_name, r.reporter_phone, r.location, r.note
  FROM public_reports r
  LEFT JOIN blacklist bl2 ON bl2.plate_no = r.plate_no AND bl2.is_active=1
  $plateCondRep
) z
$hitCond
ORDER BY created_at DESC
LIMIT 300";
$inc = q($db,$sqlInc);
$incRows='';
while($x=mysqli_fetch_assoc($inc)){
  $src = e($x['src']); $sid=(int)$x['src_id']; $plate=e($x['plate']); $ts=e($x['created_at']);
  $hitTag = ((int)$x['hit']===1) ? "<span class='tag hit'>命中</span>" : "<span class='tag'>—</span>";
  $srcTag = "<span class='tag src'>".$src."</span>";
  $extra = '';
  if($src==='外勤偵測' && $x['image_id']){
    $iid=(int)$x['image_id']; $extra="<img class='thumb' src='console.php?img=$iid' alt='img'>";
  }else{
    $rn=e($x['reporter_name']); $rp=e($x['reporter_phone']); $loc=e($x['location']); $note=e($x['note']);
    $meta=[]; if($rn!=='') $meta[]="姓名:$rn"; if($rp!=='') $meta[]="電話:$rp"; if($loc!=='') $meta[]="地點:$loc"; if($note!=='') $meta[]="備註:$note";
    $extra=$meta?("<div class='meta'>".implode('　',$meta)."</div>"):'';
  }
  if($user['role']==='admin' && (int)$x['hit']!==1 && $plate!==''){
    $quick="<form method='post' class='inline'><input type='hidden' name='act' value='bl_quick_add'><input type='hidden' name='plate_no' value='".e($x['plate'])."'><input class='ipt' name='reason' placeholder='原因（可空白）' style='max-width:220px'><button class='btn btn-mini' type='submit'>加入黑名單</button></form>";
  }else{ $quick='—'; }
  $incRows.="<tr><td>$srcTag</td><td>$sid</td><td>".($plate!==''?$plate:'—')."</td><td>$hitTag</td><td>$ts</td><td>$extra</td><td>$quick</td></tr>";
}

// === 匯入結果區塊 ===
$importResultsHtml = '';
if(!empty($_SESSION['import_results'])){
  $importResultsHtml .= "<div class='card' style='margin-top:10px'><h3>匯入結果</h3><div style='overflow:auto'><table class='table'><thead><tr><th>帳號</th><th>角色</th><th>狀態</th><th>暫時/指定密碼</th></tr></thead><tbody>";
  foreach($_SESSION['import_results'] as $r){
    $importResultsHtml .= "<tr><td>".e($r[0])."</td><td>".e($r[1])."</td><td>".e($r[2])."</td><td>".e($r[3])."</td></tr>";
  }
  $importResultsHtml .= "</tbody></table></div></div>";
  unset($_SESSION['import_results']);
}

// === 使用者列表 ===
$usersRows='';
$ul=q($db,"SELECT id,username,role,created_at FROM users ORDER BY id DESC LIMIT 500");
while($row=mysqli_fetch_assoc($ul)){
  $id=(int)$row['id']; $name=e($row['username']); $role=e($row['role']); $ts=e($row['created_at']);
  if($user['role']==='admin'){
    $roleCtl = "<form method='post' class='inline'><input type='hidden' name='act' value='u_role'><input type='hidden' name='id' value='$id'><select name='role' class='sel'><option value='admin' ".($role==='admin'?'selected':'').">admin</option><option value='officer' ".($role==='officer'?'selected':'').">officer</option></select><button class='btn btn-mini' type='submit'>存</button></form>";
    $setPw  = "<form method='post' class='inline'><input type='hidden' name='act' value='u_setpw'><input type='hidden' name='id' value='$id'><input class='ipt' type='password' name='newpw' placeholder='新密碼' style='max-width:140px'><input class='ipt' type='password' name='newpw2' placeholder='再輸入' style='max-width:140px'><button class='btn btn-mini' type='submit'>設置密碼</button></form>";
    $ops    = "<form method='post' class='inline'><input type='hidden' name='act' value='u_reset'><input type='hidden' name='id' value='$id'><button class='btn btn-mini' type='submit'>重設密碼</button></form> <form method='post' class='inline' onsubmit=\"return confirm('確定刪除？')\"><input type='hidden' name='act' value='u_delete'><input type='hidden' name='id' value='$id'><button class='btn btn-mini' type='submit'>刪除</button></form>";
  }else{ $roleCtl=$role; $setPw='—'; $ops='—'; }
  $usersRows.="<tr><td>$id</td><td>$name</td><td>$roleCtl</td><td>$ts</td><td>$setPw $ops</td></tr>";
}

// === RWD / UI ===
$css=<<<CSS
:root{--bg:#0b1020;--card:#111827;--muted:#9ca3af;--text:#e5e7eb;--pri:#2563eb;--pri-2:#1f2937}
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);margin:0}
.nav{position:sticky;top:0;z-index:20;display:flex;gap:8px;flex-wrap:wrap;align-items:center;background:#0f172a;padding:10px 12px;border-bottom:1px solid #1f2937}
.brand{font-weight:700;margin-right:auto;color:#93c5fd}
.nav a,.btn{display:inline-flex;align-items:center;gap:6px;background:var(--pri-2);color:#fff;text-decoration:none;border:1px solid #2b3444;border-radius:10px;padding:8px 12px;cursor:pointer}
.btn.btn-mini{padding:6px 8px;font-size:12px}
.container{max-width:1200px;margin:18px auto;padding:0 12px;display:grid;gap:16px}
.card{background:var(--card);border:1px solid #273244;border-radius:14px;padding:16px}
.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid #223047;padding:10px;text-align:left;vertical-align:top}
.table th{position:sticky;top:0;background:#101827}
input[type=file],.ipt,.sel,textarea.ipt{padding:10px;background:#0f172a;border:1px solid #374151;color:#e5e7eb;border-radius:10px}
.thumb{height:60px;border-radius:8px}
.flash{padding:8px 12px;border-radius:10px;margin:8px 0}
.flash.ok{background:#0f2f26;color:#a7f3d0;border:1px solid #1b4d3f}
.flash.err{background:#3f1d1d;color:#fecaca;border:1px solid #5b2727}
.inline{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #2b3444;background:#0f172a;color:#cbd5e1;font-size:12px}
.tag.hit{background:#113022;color:#86efac;border-color:#164a3a}
.tag.src{background:#1c2030;color:#a5b4fc;border-color:#2b3444}
.meta{color:#cbd5e1}
@media (max-width:720px){ .table{display:block;overflow:auto} }
CSS;

$flash='';
if(!empty($_SESSION['flash_ok'])){ $flash="<div class='flash ok'>".e($_SESSION['flash_ok'])."</div>"; unset($_SESSION['flash_ok']); }
elseif(!empty($_SESSION['flash_err'])){ $flash="<div class='flash err'>".e($_SESSION['flash_err'])."</div>"; unset($_SESSION['flash_err']); }

// 自己帳號資訊
$me = null;
$meq = q($db,"SELECT id,username,role,created_at FROM users WHERE id=".(int)$user['id']." LIMIT 1");
$me = mysqli_fetch_assoc($meq);
$uName=e($me['username'] ?? $user['username']);
$uRole=e($me['role'] ?? $user['role']);
$uCreated=e($me['created_at'] ?? '');

$qinc = $qinc ?? '';
$qincHtml = e($qinc);
$onlyHitChecked = $onlyHit ? 'checked' : '';

// === 輸出 ===
echo <<<HTML
<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MPolice 後台</title>
<link rel="icon" href="data:,"><style>$css</style>
</head>
<body>
  <div class="nav">
    <div class="brand">M-Police 資訊系統後台</div>
    <a href="#blacklist">黑名單</a>
    <a href="#incidents">事件匯總</a>
    <a href="#users">使用者/匯入</a>
    <a href="#account">我的帳號</a>
    <a href="console.php?logout=1">登出（{$uName} / {$uRole}）</a>
  </div>

  <div class="container">
    $flash

    <div class="card" id="blacklist">
      <h2>黑名單管理（admin）</h2>
      <form method="post" class="tools">
        <input type="hidden" name="act" value="bl_add">
        <input class="ipt" name="plate_no" placeholder="車牌" required>
        <input class="ipt" name="reason" placeholder="原因（可空白）">
        <button class="btn" type="submit">新增/啟用</button>
      </form>
      <div style="overflow:auto;margin-top:10px">
        <table class="table">
          <thead><tr><th>ID</th><th>車牌</th><th>原因</th><th>狀態</th><th>操作</th></tr></thead>
          <tbody>$blRows</tbody>
        </table>
      </div>
    </div>

    <div class="card" id="incidents">
      <h2>事件匯總（民眾舉報＋外勤偵測）</h2>
      <form method="get" action="#incidents" class="tools">
        <input class="ipt" name="qinc" value="{$qincHtml}" placeholder="依車牌查詢（含模糊）">
        <label class="inline" style="gap:6px"><input type="checkbox" name="only_hit" value="1" {$onlyHitChecked}> 僅顯示命中</label>
        <button class="btn" type="submit">查詢</button>
        <a class="btn" href="console.php#incidents">清除</a>
      </form>
      <div style="overflow:auto;margin-top:10px">
        <table class="table">
          <thead><tr><th>來源</th><th>來源ID</th><th>車牌</th><th>黑名單</th><th>時間</th><th>附加資訊</th><th>快捷操作</th></tr></thead>
          <tbody>$incRows</tbody>
        </table>
      </div>
    </div>

    <div class="card" id="users">
      <h2>使用者管理與匯入（admin）</h2>
      <div style="color:#9ca3af;margin-bottom:6px">
        CSV 欄位支援：<code>username,role[,password]</code>；角色 admin/officer 或 中文 管理員/員警。
        若提供第三欄 <code>password</code>，將直接採用該密碼；未提供則自動產生。
      </div>
      <form method="post" enctype="multipart/form-data" class="tools">
        <input type="hidden" name="act" value="u_import">
        <input type="file" name="csvfile" accept=".csv,text/csv">
        <button class="btn" type="submit">上傳 CSV</button>
      </form>
      <form method="post" class="tools" style="margin-top:8px">
        <input type="hidden" name="act" value="u_import">
        <textarea class="ipt" name="csv" placeholder="例如：&#10;jack,officer,Passw0rd&#10;amy,管理員&#10;leo,officer,My@12345" style="min-height:120px;width:100%"></textarea>
        <button class="btn" type="submit">貼上匯入</button>
      </form>
      $importResultsHtml
      <div style="overflow:auto;margin-top:10px">
        <table class="table">
          <thead><tr><th>ID</th><th>帳號</th><th>角色</th><th>建立時間</th><th>操作</th></tr></thead>
          <tbody>$usersRows</tbody>
        </table>
      </div>
    </div>

    <div class="card" id="account">
      <h2>我的帳號</h2>
      <div style="color:#9ca3af;margin-bottom:8px">
        帳號：<b>{$uName}</b>　角色：<b>{$uRole}</b>　建立時間：<b>{$uCreated}</b>
      </div>
      <form method="post" class="tools">
        <input type="hidden" name="act" value="self_pw">
        <input class="ipt" type="password" name="oldpw" placeholder="舊密碼" required>
        <input class="ipt" type="password" name="newpw" placeholder="新密碼（至少 6 碼）" required>
        <input class="ipt" type="password" name="newpw2" placeholder="再次輸入新密碼" required>
        <button class="btn" type="submit">更新我的密碼</button>
      </form>
    </div>

  </div>
</body></html>
HTML;
