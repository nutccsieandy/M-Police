<?php
// test_api.php － 透過表單上傳圖片 → 呼叫 FastAPI /detect → 顯示回傳

function h($s){ return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

$apiUrl = 'http://127.0.0.1:8000/detect';
$result = null;    // 原始字串
$pretty = null;    // 美化後 JSON
$error  = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {
    $f = $_FILES['image'];
    if ($f['error'] !== UPLOAD_ERR_OK) {
        $error = '上傳失敗，錯誤代碼：'.$f['error'];
    } else {
        $tmp  = $f['tmp_name'];
        $mime = mime_content_type($tmp) ?: 'application/octet-stream';
        $name = $f['name'];

        // 呼叫 FastAPI
        $ch = curl_init($apiUrl);
        $post = ['file' => new CURLFile($tmp, $mime, $name)];
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $post,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
        ]);
        $resp = curl_exec($ch);
        if ($resp === false) {
            $error = 'cURL 錯誤：'.curl_error($ch);
        } else {
            $result = $resp;
            $j = json_decode($resp, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $pretty = json_encode($j, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT);
            }
        }
        curl_close($ch);
    }
}
?>
<!doctype html>
<html lang="zh-TW">
<head>
<meta charset="utf-8">
<title>API 上傳測試 - /detect</title>
<style>
body{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial;margin:24px}
.card{border:1px solid #ddd;border-radius:12px;padding:16px;max-width:760px}
pre{background:#0b1020;color:#e6eef7;padding:12px;border-radius:8px;overflow:auto}
.err{background:#3a161b;color:#ffd7d7;padding:10px;border-radius:8px;margin:10px 0}
.ok{background:#11351b;color:#c9ffd7;padding:10px;border-radius:8px;margin:10px 0}
</style>
</head>
<body>
<div class="card">
  <h2>FastAPI /detect 上傳測試</h2>
  <p>API：<code><?=h($apiUrl)?></code></p>

  <form method="post" enctype="multipart/form-data">
    <input type="file" name="image" accept="image/*" required>
    <button type="submit">上傳並送到 /detect</button>
  </form>

  <?php if ($error): ?>
    <div class="err">❌ <?=h($error)?></div>
  <?php endif; ?>

  <?php if ($result !== null): ?>
    <div class="ok">✅ 呼叫成功，原始回應：</div>
    <pre><?=h($result)?></pre>

    <?php if ($pretty !== null): ?>
      <div class="ok">🔎 JSON（排版後）：</div>
      <pre><?=h($pretty)?></pre>
      <?php
        $data = json_decode($result, true);
        if (isset($data['plate_text'])) {
            echo '<p>📌 偵測到的車牌：<b>'.h($data['plate_text']).'</b></p>';
        }
      ?>
    <?php endif; ?>
  <?php endif; ?>
</div>
</body>
</html>
