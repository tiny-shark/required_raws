<?php
/**
 * File Manager - PHP 5.4 compatible (final)
 *
 * - Monaco editor integration (editor height 240px)
 * - Editor is disabled until a file is selected
 * - Ctrl+S saves (submits form)
 * - Header shows centered notifications (e.g. "✅ File saved")
 * - Header title: "TINYSHARK CO PANEL"
 * - Client IP shown at top-right, left of Home button
 * - Sidebar controls arranged as in screenshot:
 *     Row Search (top)
 *     Row Upload (middle)
 *     Row Create (bottom)
 * - Select/option visibility fixes
 *
 * SECURITY: This tool runs powerful operations. Use only in secure/test environments.
 */

/* ---------------- CONFIG ---------------- */

$DEV_LOCK_ENABLED = true;
$ALLOWED_IPS = array('1.2.3.4', '5.6.7.8');

if ($DEV_LOCK_ENABLED) {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    if (!in_array($ip, $ALLOWED_IPS, true)) {
        http_response_code(403);
        echo "Forbidden";
        exit;
    }
}


$DEBUG = true;
$BASE_DIR = '/';
$ADMIN_USER = 'admin';
$ADMIN_PASS_RAW = 'AdminPass123!'; // CHANGE THIS

/* ---------- BOOT ---------- */
if ($DEBUG) {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
}
if (session_id() === '') session_start();

/* ---------- HELPERS (PHP 5.4 compatible) ---------- */
if (!function_exists('hash_equals')) {
    function hash_equals_compat($a, $b) {
        if (!is_string($a) || !is_string($b)) return false;
        $la = strlen($a); $lb = strlen($b);
        if ($la !== $lb) return false;
        $res = 0;
        for ($i = 0; $i < $la; $i++) $res |= ord($a[$i]) ^ ord($b[$i]);
        return $res === 0;
    }
} else {
    function hash_equals_compat($a, $b) { return hash_equals($a, $b); }
}

function random_token($length = 32) {
    if (function_exists('openssl_random_pseudo_bytes')) {
        $rb = openssl_random_pseudo_bytes($length);
        if ($rb !== false) return bin2hex($rb);
    }
    $chars = '0123456789abcdef';
    $out = '';
    for ($i = 0; $i < $length * 2; $i++) $out .= $chars[mt_rand(0, 15)];
    return $out;
}

function csrf_token() {
    if (empty($_SESSION['fm_csrf'])) $_SESSION['fm_csrf'] = random_token(16);
    return $_SESSION['fm_csrf'];
}

function check_csrf($t) {
    if (!isset($_SESSION['fm_csrf'])) return false;
    if (!is_string($t)) return false;
    return hash_equals_compat($_SESSION['fm_csrf'], (string)$t);
}

function realpath_in_base($relative) {
    global $REAL_BASE;
    if (!is_string($relative) || $relative === '') return false;
    $relative = str_replace(array("\0"), '', $relative);
    $relative = str_replace('\\', '/', $relative);
    $relative = ltrim($relative, '/');
    $candidate = realpath($REAL_BASE . '/' . $relative);
    if ($candidate === false) return false;
    $realBase = rtrim($REAL_BASE, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    $candidateNorm = rtrim($candidate, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if (strpos($candidateNorm, $realBase) === 0) return rtrim($candidate, DIRECTORY_SEPARATOR);
    return false;
}
/* --- NEW: safe temp filename helper --- */
function fm_temp_zip_path($prefix = 'fm_', $suffix = '.zip') {
    $dir = sys_get_temp_dir();
    $tmp = tempnam($dir, $prefix);
    if ($tmp === false) return false;
    // tempnam creates a file; rename to .zip
    $zipPath = $tmp . $suffix;
    @unlink($tmp);
    return $zipPath;
}

/* --- NEW: add folder to ZipArchive recursively --- */
function fm_zip_add_dir($zip, $dirReal, $localBase) {
    $dirReal = rtrim($dirReal, DIRECTORY_SEPARATOR);
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dirReal, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($it as $fileinfo) {
        $path = $fileinfo->getRealPath();
        if ($path === false) continue;

        $rel = substr($path, strlen($dirReal) + 1);
        $rel = str_replace('\\', '/', $rel);
        $zipPath = ($localBase !== '' ? ($localBase . '/') : '') . $rel;

        if ($fileinfo->isDir()) {
            $zip->addEmptyDir(rtrim($zipPath, '/'));
        } else {
            $zip->addFile($path, $zipPath);
        }
    }
}

/* --- Sidebar icon helper (extension-based) --- */
function fm_icon_for($is_dir, $name) {
    if ($is_dir) return "📁";
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));

    // Archives
    if (in_array($ext, array('zip','rar','7z','tar','gz','bz2'))) return "🗜️";

    // Images
    if (in_array($ext, array('png','jpg','jpeg','gif','webp','svg','ico','bmp'))) return "🖼️";

    // Video
    if (in_array($ext, array('mp4','mkv','avi','mov','webm','wmv','flv','m4v'))) return "🎬";

    // Audio
    if (in_array($ext, array('mp3','wav','ogg','m4a','flac','aac','wma'))) return "🎵";

    // Docs
    if ($ext === 'pdf') return "📄";
    if (in_array($ext, array('doc','docx','rtf','odt'))) return "📃";
    if (in_array($ext, array('xls','xlsx','csv','ods'))) return "📊";
    if (in_array($ext, array('ppt','pptx','odp'))) return "📽️";

    // Config / data
    if ($ext === 'json') return "🧾";
    if (in_array($ext, array('xml','yml','yaml','ini','conf','env','config'))) return "⚙️";

    // Code
    if (in_array($ext, array('php','js','ts','css','scss','less','html','htm','py','java','cs','cpp','c','h','go','rb','rs','swift','kt','sh','bash','sql'))) {
        if ($ext === 'sql') return "🗄️";
        return "🧩";
    }

    // Text
    if (in_array($ext, array('txt','log','md','readme'))) return "📝";

    // Default
    return "📄";
}

/* ---------- PREPARE BASE DIR ---------- */
if (!is_dir($BASE_DIR)) @mkdir($BASE_DIR, 0777, true);
$REAL_BASE = realpath($BASE_DIR);
if ($REAL_BASE === false) {
    $fallback = __DIR__ . '/storage';
    if (!is_dir($fallback)) @mkdir($fallback, 0777, true);
    $REAL_BASE = realpath($fallback);
    if ($REAL_BASE === false) {
        http_response_code(500);
        echo "Server config error: cannot create working directory.";
        if ($DEBUG) echo "<pre>BASE_DIR={$BASE_DIR}\nFALLBACK={$fallback}</pre>";
        exit;
    }
}

/* ---------- AUTH ---------- */
function is_logged_in() { return !empty($_SESSION['fm_user']); }

$action = isset($_GET['action']) ? $_GET['action'] : '';

/* ---------- VERİTABANI YÖNETİMİ ---------- */
if ($action === 'db_connect') {
    header('Content-Type: application/json');
    $resp = array('ok' => false, 'msg' => '', 'error' => '');
    
    $csrf_in = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    if (!check_csrf($csrf_in)) { $resp['error'] = 'CSRF error'; echo json_encode($resp); exit; }
    
    $type = isset($_POST['type']) ? $_POST['type'] : 'mysql';
    $host = isset($_POST['host']) ? $_POST['host'] : 'localhost';
    $port = isset($_POST['port']) ? intval($_POST['port']) : ($type === 'mysql' ? 3306 : 5432);
    $user = isset($_POST['user']) ? $_POST['user'] : '';
    $pass = isset($_POST['pass']) ? $_POST['pass'] : '';
    $dbname = isset($_POST['dbname']) ? $_POST['dbname'] : '';
    
    try {
        if ($type === 'mysql') {
            $link = @mysql_connect($host . ':' . $port, $user, $pass);
            if (!$link) throw new Exception(mysql_error());
            if ($dbname && !@mysql_select_db($dbname, $link)) {
                throw new Exception(mysql_error($link));
            }
            $_SESSION['db_type'] = 'mysql';
            $_SESSION['db_link'] = serialize($link);
            $resp['ok'] = true;
            $resp['msg'] = 'MySQL bağlantısı başarılı';
        } elseif ($type === 'postgresql' && function_exists('pg_connect')) {
            $conn_str = "host=$host port=$port user=$user password=$pass";
            if ($dbname) $conn_str .= " dbname=$dbname";
            $link = @pg_connect($conn_str);
            if (!$link) throw new Exception(pg_last_error());
            $_SESSION['db_type'] = 'postgresql';
            $_SESSION['db_link'] = serialize($link);
            $resp['ok'] = true;
            $resp['msg'] = 'PostgreSQL bağlantısı başarılı';
        } else {
            throw new Exception('Database type not supported');
        }
        
        $_SESSION['db_host'] = $host;
        $_SESSION['db_user'] = $user;
        $_SESSION['db_name'] = $dbname;
        
    } catch (Exception $e) {
        $resp['error'] = 'Bağlantı hatası: ' . $e->getMessage();
    }
    
    echo json_encode($resp);
    exit;
}

if ($action === 'db_query') {
    header('Content-Type: application/json');
    $resp = array('ok' => false, 'data' => array(), 'error' => '', 'affected' => 0, 'time' => 0);
    
    $csrf_in = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    if (!check_csrf($csrf_in)) { $resp['error'] = 'CSRF error'; echo json_encode($resp); exit; }
    
    if (!isset($_SESSION['db_link']) || !isset($_SESSION['db_type'])) {
        $resp['error'] = 'No active database connection';
        echo json_encode($resp); exit;
    }
    
    $query = isset($_POST['query']) ? $_POST['query'] : '';
    if (empty($query)) { $resp['error'] = 'Empty query'; echo json_encode($resp); exit; }
    
    $type = $_SESSION['db_type'];
    $link = unserialize($_SESSION['db_link']);
    
    $start = microtime(true);
    
    try {
        if ($type === 'mysql') {
            $result = @mysql_query($query, $link);
            if (!$result) throw new Exception(mysql_error($link));
            
            if (is_resource($result)) {
            $rows = array();
            while ($row = mysql_fetch_assoc($result)) {
                $rows[] = $row;
            }
            $resp['data'] = $rows;
            $resp['affected'] = count($rows);
            mysql_free_result($result);
        } else {
            $resp['affected'] = mysql_affected_rows($link);
            $resp['insert_id'] = mysql_insert_id($link);
        }
            $resp['ok'] = true;
            
        } elseif ($type === 'postgresql') {
            $result = @pg_query($link, $query);
            if (!$result) throw new Exception(pg_last_error($link));
            
            if (pg_num_rows($result) > 0) {
                $rows = array();
                while ($row = pg_fetch_assoc($result)) {
                    $rows[] = $row;
                }
                $resp['data'] = $rows;
                $resp['affected'] = pg_num_rows($result);
            } else {
                $resp['affected'] = pg_affected_rows($result);
            }
            pg_free_result($result);
            $resp['ok'] = true;
        }
        
    } catch (Exception $e) {
        $resp['error'] = 'Query error: ' . $e->getMessage();
    }
    
    $resp['time'] = round((microtime(true) - $start) * 1000, 2);
    echo json_encode($resp);
    exit;
}

if ($action === 'db_tables') {
    header('Content-Type: application/json');
    $resp = array('ok' => false, 'tables' => array(), 'error' => '');
    
    if (!isset($_SESSION['db_link']) || !isset($_SESSION['db_type'])) {
        $resp['error'] = 'No active database connection';
        echo json_encode($resp); exit;
    }
    
    $type = $_SESSION['db_type'];
    $link = unserialize($_SESSION['db_link']);
    
    try {
        if ($type === 'mysql') {
            $result = mysql_query("SHOW TABLES", $link);
            if (!$result) throw new Exception(mysql_error($link));
            
            while ($row = mysql_fetch_row($result)) {
                $resp['tables'][] = $row[0];
            }
            mysql_free_result($result);
            
        } elseif ($type === 'postgresql') {
            $result = pg_query($link, "SELECT tablename FROM pg_tables WHERE schemaname = 'public'");
            if (!$result) throw new Exception(pg_last_error($link));
            
            while ($row = pg_fetch_row($result)) {
                $resp['tables'][] = $row[0];
            }
            pg_free_result($result);
        }
        
        $resp['ok'] = true;
    } catch (Exception $e) {
        $resp['error'] = $e->getMessage();
    }
    
    echo json_encode($resp);
    exit;
}

if ($action === 'db_structure') {
    header('Content-Type: application/json');
    $resp = array('ok' => false, 'structure' => '', 'error' => '');
    
    if (!isset($_SESSION['db_link']) || !isset($_SESSION['db_type'])) {
        $resp['error'] = 'No active database connection';
        echo json_encode($resp); exit;
    }
    
    $table = isset($_GET['table']) ? $_GET['table'] : '';
    if (empty($table)) { $resp['error'] = 'No table specified'; echo json_encode($resp); exit; }
    
    $type = $_SESSION['db_type'];
    $link = unserialize($_SESSION['db_link']);
    
    try {
        if ($type === 'mysql') {
            $result = mysql_query("SHOW CREATE TABLE `" . mysql_real_escape_string($table) . "`", $link);
            if (!$result) throw new Exception(mysql_error($link));
            
            $row = mysql_fetch_assoc($result);
            $resp['structure'] = $row['Create Table'];
            mysql_free_result($result);
            
        } elseif ($type === 'postgresql') {
            $result = pg_query($link, "SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_name = '" . pg_escape_string($table) . "'");
            if (!$result) throw new Exception(pg_last_error($link));
            
            $structure = "Table: $table\n\n";
            while ($row = pg_fetch_assoc($result)) {
                $structure .= sprintf("%-20s %-20s %s\n", 
                    $row['column_name'], 
                    $row['data_type'], 
                    $row['is_nullable'] === 'YES' ? 'NULL' : 'NOT NULL');
            }
            pg_free_result($result);
            $resp['structure'] = $structure;
        }
        
        $resp['ok'] = true;
    } catch (Exception $e) {
        $resp['error'] = $e->getMessage();
    }
    
    echo json_encode($resp);
    exit;
}

if ($action === 'login') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $user = isset($_POST['user']) ? $_POST['user'] : '';
        $pass = isset($_POST['pass']) ? $_POST['pass'] : '';
        if ($user === $GLOBALS['ADMIN_USER'] && $pass === $GLOBALS['ADMIN_PASS_RAW']) {
            $_SESSION['fm_user'] = $user;
            unset($_SESSION['fm_csrf']);
            csrf_token();
            header('Location: ?');
            exit;
        } else {
            $error_login = "Login failed.";
        }
    }
    ?>
    <!doctype html><html><head><meta charset="utf-8"><title>Admin Login</title>
    <style>body{font-family:Arial,Helvetica,sans-serif;background:#0f1720;color:#e6eef6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}.card{background:#0b1220;padding:28px;border-radius:12px;width:360px;box-shadow:0 10px 30px rgba(2,6,23,.6)}input{width:100%;padding:10px;margin:8px 0;border-radius:6px;border:1px solid #223248;background:#081019;color:#fff}button{width:100%;padding:10px;border-radius:6px;border:none;background:#3b82f6;color:#fff;font-weight:700}.err{background:#7f1d1d;padding:8px;border-radius:6px;margin-bottom:8px}</style>
    </head><body>
    <div class="card">
        <h2>🔐 Admin Login</h2>
        <?php if (!empty($error_login)): ?><div class="err"><?php echo htmlspecialchars($error_login); ?></div><?php endif; ?>
        <form method="post">
            <input name="user" placeholder="User" required autofocus>
            <input type="password" name="pass" placeholder="Password" required>
            <button>Login</button>
        </form>
    </div>
    </body></html>
    <?php
    exit;
}

if ($action === 'logout') {
    session_destroy();
    header('Location: ?action=login');
    exit;
}

if (!is_logged_in()) {
    header('Location: ?action=login');
    exit;
}

/* ---------- CURRENT DIRECTORY ---------- */
$req_dir = isset($_GET['dir']) ? $_GET['dir'] : '';
$req_dir = trim(str_replace(array('..', "\0", '\\'), '', $req_dir), '/');
$current_real = $REAL_BASE . ($req_dir ? '/' . $req_dir : '');
if (!is_dir($current_real)) @mkdir($current_real, 0777, true);
$current_real = realpath($current_real) ?: $REAL_BASE;
$current_rel = $req_dir;

/* ---------- SEARCH ENDPOINT ---------- */
if ($action === 'search') {
    $q = isset($_GET['q']) ? trim($_GET['q']) : '';
    $type = isset($_GET['type']) ? $_GET['type'] : 'name';
    $out = array('ok' => false, 'results' => array(), 'error' => '');
    if ($q === '') {
        $out['error'] = 'Empty query';
        header('Content-Type: application/json'); echo json_encode($out); exit;
    }
    $results = array();
    $maxResults = 200;
    if ($type === 'name') {
        $items = is_dir($current_real) ? array_values(array_diff(scandir($current_real), array('.', '..'))) : array();
        foreach ($items as $item) {
            if (count($results) >= $maxResults) break;
            if (function_exists('mb_stripos')) {
                $hit = (mb_stripos($item, $q, 0, 'UTF-8') !== false);
            } else {
                $hit = (stripos($item, $q) !== false);
            }
            if ($hit) {
                $results[] = array(
                    'path' => ($current_rel ? $current_rel . '/' . $item : $item),
                    'is_dir' => is_dir($current_real . '/' . $item) ? 1 : 0,
                    'matchType' => 'name',
                    'snippet' => ''
                );
            }
        }
    } else {
        $textExt = array('php','txt','md','html','htm','css','js','json','xml','py','sh','ini','conf','log','csv','sql');
        $maxFiles = 500; $filesScanned = 0; $maxFileSize = 1024 * 100;
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($current_real, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
        foreach ($iterator as $fileinfo) {
            if (count($results) >= $maxResults) break;
            if ($filesScanned >= $maxFiles) break;
            $filesScanned++;
            if (!$fileinfo->isFile()) continue;
            $filePath = $fileinfo->getRealPath();
            $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
            if (!in_array($ext, $textExt)) continue;
            if ($fileinfo->getSize() > 5 * 1024 * 1024) continue;
            $handle = @fopen($filePath, 'r');
            if (!$handle) continue;
            $content = ''; $read = 0;
            while (!feof($handle) && $read < $maxFileSize) {
                $buf = fread($handle, 4096);
                if ($buf === false) break;
                $content .= $buf; $read += strlen($buf);
            }
            fclose($handle);
            if ($content === '') continue;

            if (function_exists('mb_stripos')) {
                $hit = (mb_stripos($content, $q, 0, 'UTF-8') !== false);
                $pos = $hit ? mb_stripos($content, $q, 0, 'UTF-8') : false;
                $start = ($pos !== false) ? max(0, $pos - 60) : 0;
                $snippet = ($pos !== false) ? mb_substr($content, $start, 240, 'UTF-8') : '';
            } else {
                $hit = (stripos($content, $q) !== false);
                $pos = $hit ? stripos($content, $q) : false;
                $start = ($pos !== false) ? max(0, $pos - 60) : 0;
                $snippet = ($pos !== false) ? substr($content, $start, 240) : '';
            }

            if ($hit) {
                $results[] = array(
                    'path' => substr($filePath, strlen($REAL_BASE) + 1),
                    'is_dir' => 0,
                    'matchType' => 'content',
                    'snippet' => $snippet
                );
            }
        }
    }
    $out['ok'] = true; $out['results'] = $results;
    header('Content-Type: application/json'); echo json_encode($out); exit;
}

/* ---------- GELİŞMİŞ ARAMA ---------- */
if ($action === 'advanced_search') {
    header('Content-Type: application/json');
    $resp = array('ok' => false, 'results' => array(), 'count' => 0, 'error' => '');
    
    $csrf_in = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    if (!check_csrf($csrf_in)) { $resp['error'] = 'CSRF error'; echo json_encode($resp); exit; }
    
    $search_type = isset($_POST['search_type']) ? $_POST['search_type'] : 'name';
    $query = isset($_POST['query']) ? trim($_POST['query']) : '';
    $size_min = isset($_POST['size_min']) ? intval($_POST['size_min']) : 0;
    $size_max = isset($_POST['size_max']) ? intval($_POST['size_max']) : 0;
    $date_from = isset($_POST['date_from']) ? strtotime($_POST['date_from']) : 0;
    $date_to = isset($_POST['date_to']) ? strtotime($_POST['date_to']) : 0;
    $extensions = isset($_POST['extensions']) ? explode(',', trim($_POST['extensions'])) : array();
    $case_sensitive = isset($_POST['case_sensitive']) ? true : false;
    $use_regex = isset($_POST['use_regex']) ? true : false;
    $max_results = isset($_POST['max_results']) ? intval($_POST['max_results']) : 500;
    
    if (empty($query) && $search_type !== 'advanced') {
        $resp['error'] = 'Arama sorgusu boş';
        echo json_encode($resp); exit;
    }
    
    $results = array();
    $scanned = 0;
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($current_real, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    
    foreach ($iterator as $fileinfo) {
        if (count($results) >= $max_results) break;
        if ($scanned++ > 5000) break; // Güvenlik limiti
        
        $path = $fileinfo->getRealPath();
        $rel_path = substr($path, strlen($REAL_BASE) + 1);
        $name = $fileinfo->getFilename();
        $is_dir = $fileinfo->isDir();
        $size = $fileinfo->getSize();
        $mtime = $fileinfo->getMTime();
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        
        // Boyut filtresi
        if ($size_min > 0 && $size < $size_min) continue;
        if ($size_max > 0 && $size > $size_max) continue;
        
        // Tarih filtresi
        if ($date_from > 0 && $mtime < $date_from) continue;
        if ($date_to > 0 && $mtime > $date_to) continue;
        
        // Uzantı filtresi
        if (!empty($extensions) && !in_array($ext, $extensions) && !$is_dir) continue;
        
        // Arama kriterleri
        $match = false;
        $match_details = '';
        
        switch ($search_type) {
            case 'name':
                if ($use_regex) {
                    $match = @preg_match('/' . $query . '/', $name);
                } else {
                    if ($case_sensitive) {
                        $match = (strpos($name, $query) !== false);
                    } else {
                        $match = (stripos($name, $query) !== false);
                    }
                }
                $match_details = 'Name match';
                break;
                
            case 'content':
                if ($is_dir || $size > 5 * 1024 * 1024) continue;
                
                $handle = @fopen($path, 'r');
                if (!$handle) continue;
                
                $content = '';
                $read = 0;
                while (!feof($handle) && $read < 1024 * 100) {
                    $buf = fread($handle, 4096);
                    if ($buf === false) break;
                    $content .= $buf;
                    $read += strlen($buf);
                    
                    // Early match check
                    if ($use_regex) {
                        $match = @preg_match('/' . $query . '/', $content);
                    } else {
                        if ($case_sensitive) {
                            $match = (strpos($content, $query) !== false);
                        } else {
                            $match = (stripos($content, $query) !== false);
                        }
                    }
                    if ($match) break;
                }
                fclose($handle);
                
                if (!$match) {
                    // Tam dosyayı kontrol et
                    if ($use_regex) {
                        $match = @preg_match('/' . $query . '/', file_get_contents($path));
                    } else {
                        $content = file_get_contents($path);
                        if ($case_sensitive) {
                            $match = (strpos($content, $query) !== false);
                        } else {
                            $match = (stripos($content, $query) !== false);
                        }
                    }
                }
                
                $match_details = 'Content match';
                break;
                
            case 'advanced':
                // Çoklu kriter arama
                $name_match = true;
                $content_match = true;
                
                $name_query = isset($_POST['name_query']) ? trim($_POST['name_query']) : '';
                $content_query = isset($_POST['content_query']) ? trim($_POST['content_query']) : '';
                
                if (!empty($name_query)) {
                    if ($use_regex) {
                        $name_match = @preg_match('/' . $name_query . '/', $name);
                    } else {
                        if ($case_sensitive) {
                            $name_match = (strpos($name, $name_query) !== false);
                        } else {
                            $name_match = (stripos($name, $name_query) !== false);
                        }
                    }
                }
                
                if (!empty($content_query) && !$is_dir && $size < 5 * 1024 * 1024) {
                    $content = file_get_contents($path);
                    if ($use_regex) {
                        $content_match = @preg_match('/' . $content_query . '/', $content);
                    } else {
                        if ($case_sensitive) {
                            $content_match = (strpos($content, $content_query) !== false);
                        } else {
                            $content_match = (stripos($content, $content_query) !== false);
                        }
                    }
                }
                
                $match = $name_match && $content_match;
                $match_details = 'Advanced match';
                break;
        }
        
        if ($match) {
            $results[] = array(
                'path' => $rel_path,
                'name' => $name,
                'is_dir' => $is_dir ? 1 : 0,
                'size' => $size,
                'modified' => date('Y-m-d H:i:s', $mtime),
                'perms' => substr(sprintf('%o', $fileinfo->getPerms()), -4),
                'match_type' => $match_details
            );
        }
    }
    
    $resp['ok'] = true;
    $resp['results'] = $results;
    $resp['count'] = count($results);
    echo json_encode($resp);
    exit;
}

/* ---------- AJAX CHMOD ENDPOINT ---------- */
if ($action === 'chmod' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $resp = array('ok' => false, 'msg' => '', 'error' => '');
    $csrf_in = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    if (!check_csrf($csrf_in)) {
        $resp['error'] = 'CSRF error';
        header('Content-Type: application/json'); echo json_encode($resp); exit;
    }
    $path = isset($_POST['path']) ? $_POST['path'] : '';
    $modeStr = isset($_POST['mode']) ? trim($_POST['mode']) : '';
    if ($path === '' || $modeStr === '') {
        $resp['error'] = 'Missing parameters';
        header('Content-Type: application/json'); echo json_encode($resp); exit;
    }
    if (!preg_match('/^[0-7]{3,4}$/', $modeStr)) {
        $resp['error'] = 'Invalid mode format. Use 644, 0755, etc.';
        header('Content-Type: application/json'); echo json_encode($resp); exit;
    }
    if (strlen($modeStr) === 3) $modeStr = '0' . $modeStr;
    $mode = intval($modeStr, 8);

    $real = realpath_in_base($path);
    if ($real === false) {
        $resp['error'] = 'Invalid path or outside base dir';
        header('Content-Type: application/json'); echo json_encode($resp); exit;
    }
    $ok = @chmod($real, $mode);
    if ($ok) {
        $resp['ok'] = true;
        $resp['msg'] = 'Permissions changed to ' . $modeStr;
    } else {
        $resp['error'] = 'chmod failed (owner/permissions may prevent change)';
    }
    header('Content-Type: application/json'); echo json_encode($resp); exit;
}

/* ---------- AJAX ZIP EXTRACT ---------- */
if ($action === 'zip_extract' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $resp = array('ok' => false, 'msg' => '', 'error' => '');
    $csrf_in = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    if (!check_csrf($csrf_in)) { $resp['error'] = 'CSRF error'; header('Content-Type: application/json'); echo json_encode($resp); exit; }

    $path = isset($_POST['path']) ? $_POST['path'] : '';
    $target = isset($_POST['target']) ? $_POST['target'] : '';
    if ($path === '') { $resp['error'] = 'Missing path'; header('Content-Type: application/json'); echo json_encode($resp); exit; }

    $realZip = realpath_in_base($path);
    if ($realZip === false || !is_file($realZip)) { $resp['error'] = 'Invalid zip file'; header('Content-Type: application/json'); echo json_encode($resp); exit; }
    // Zip Slip engeli: zip içindeki dosya adlarını kontrol et
    
    if ($target === '' || $target === null) {
        $extractTo = $current_real;
    } else {
        $safeName = basename(str_replace(array("\0", '..'), '', $target));
        $extractTo = $current_real . '/' . $safeName;
        if (!is_dir($extractTo)) {
            if (!@mkdir($extractTo, 0777, true)) { $resp['error'] = 'Cannot create target folder'; header('Content-Type: application/json'); echo json_encode($resp); exit; }
        }
    }

    if (class_exists('ZipArchive')) {
    $za = new ZipArchive();
    $open = $za->open($realZip);
    
    if ($open === true) {
        $res = $za->extractTo($extractTo);
        $za->close();
        if ($res) { $resp['ok'] = true; $resp['msg'] = 'Extracted to ' . $extractTo; header('Content-Type: application/json'); echo json_encode($resp); exit; }
        else { $resp['error'] = 'extractTo failed'; header('Content-Type: application/json'); echo json_encode($resp); exit; }
    } else {
        $resp['error'] = 'ZipArchive open failed: code ' . intval($open);
        header('Content-Type: application/json'); echo json_encode($resp); exit;
    }
    
}

    if (function_exists('shell_exec')) {
        $cmd = 'unzip -o ' . escapeshellarg($realZip) . ' -d ' . escapeshellarg($extractTo) . ' 2>&1';
        $out = shell_exec($cmd);
        if ($out !== null) {
            $resp['ok'] = true;
            $resp['msg'] = 'Extract (shell) finished';
            $resp['out'] = $out;
            header('Content-Type: application/json'); echo json_encode($resp); exit;
        }
    }

    $resp['error'] = 'No method available to extract zip (ZipArchive or unzip required)';
    header('Content-Type: application/json'); echo json_encode($resp); exit;
}

/* ---------- AJAX ZIP ARCHIVE ---------- */
if ($action === 'zip_archive' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $resp = array('ok' => false, 'msg' => '', 'error' => '');
    $csrf_in = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    if (!check_csrf($csrf_in)) { $resp['error'] = 'CSRF error'; header('Content-Type: application/json'); echo json_encode($resp); exit; }
    $path = isset($_POST['path']) ? $_POST['path'] : '';
    $name = isset($_POST['name']) ? trim($_POST['name']) : '';
    if ($path === '') { $resp['error'] = 'Missing path'; header('Content-Type: application/json'); echo json_encode($resp); exit; }
    $realDir = realpath_in_base($path);
    if ($realDir === false || !is_dir($realDir)) { $resp['error'] = 'Invalid directory'; header('Content-Type: application/json'); echo json_encode($resp); exit; }
    if ($name === '') {
        $base = basename($realDir);
        $zipName = $base . '.zip';
    } else {
        $name = basename(str_replace(array("\0", '/','\\'), '', $name));
        if (stripos($name, '.zip') === (strlen($name)-4)) $zipName = $name; else $zipName = $name . '.zip';
    }
    $zipPath = $current_real . '/' . $zipName;
    $i = 1;
    while (file_exists($zipPath)) {
        $zipPath = $current_real . '/' . pathinfo($zipName, PATHINFO_FILENAME) . '_' . $i . '.zip';
        $i++;
    }
    if (class_exists('ZipArchive')) {
    $zip = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE) !== true) {
        $resp['error'] = 'Cannot create zip file';
        header('Content-Type: application/json'); echo json_encode($resp); exit;
    }

    $baseName = basename($realDir);
    $zip->addEmptyDir($baseName);
    fm_zip_add_dir($zip, $realDir, $baseName);

    $zip->close();
    $resp['ok'] = true;
    $resp['msg'] = 'Archive created: ' . basename($zipPath);
    header('Content-Type: application/json'); echo json_encode($resp); exit;
}
    if (function_exists('shell_exec')) {
    $srcReal = $realDir;
    $srcParent = dirname($srcReal);
    $srcBase = basename($srcReal);

    $outZip = $zipPath;

    // exit code'u yakalamak için "echo __EXIT:$?" ekliyoruz
    $cmd = 'cd ' . escapeshellarg($srcParent)
         . ' && /usr/bin/zip -r ' . escapeshellarg($outZip) . ' ' . escapeshellarg($srcBase)
         . ' 2>&1; echo "__EXIT:$?"';

    $outTxt = shell_exec($cmd);
    $exitCode = null;

    if (is_string($outTxt) && preg_match('/__EXIT:(\d+)/', $outTxt, $m)) {
        $exitCode = intval($m[1]);
        // output'tan exit satırını temizle (istersen)
        $outTxt = preg_replace('/\s*__EXIT:\d+\s*/', "\n", $outTxt);
    }

    $exists = file_exists($outZip);
    $sizeOk = ($exists && @filesize($outZip) > 0);

    if ($exitCode === 0 && $sizeOk) {
        $resp['ok'] = true;
        $resp['msg'] = 'Archive created: ' . basename($outZip);
        $resp['size'] = intval(@filesize($outZip));
        header('Content-Type: application/json'); echo json_encode($resp); exit;
    }

    // başarısızsa detay döndür
    if ($exists && !$sizeOk) { @unlink($outZip); } // 0 byte zip kalmasın
    $resp['error'] = 'zip failed';
    $resp['exit'] = $exitCode;
    $resp['zipPath'] = $outZip;
    $resp['exists'] = $exists ? 1 : 0;
    $resp['size'] = $exists ? intval(@filesize($outZip)) : 0;
    $resp['out'] = $outTxt;
    header('Content-Type: application/json'); echo json_encode($resp); exit;
}
    $resp['error'] = 'No method available to create zip (ZipArchive or zip required)';
    header('Content-Type: application/json'); echo json_encode($resp); exit;
}



/* ---------- AJAX CMD (persistent cwd like a real terminal) ---------- */
if ($action === 'ajax_cmd' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $out = array('ok' => false, 'msg' => '', 'output' => '', 'code' => 0);

    $csrf_in = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    if (!check_csrf($csrf_in)) {
        $out['msg'] = 'CSRF error';
        header('Content-Type: application/json'); echo json_encode($out); exit;
    }

    $command = isset($_POST['command']) ? trim($_POST['command']) : '';
    if ($command === '') {
        $out['msg'] = 'Empty command';
        header('Content-Type: application/json'); echo json_encode($out); exit;
    }

    // init persistent cwd (defaults to current_real)
    if (!isset($_SESSION['fm_cwd']) || !is_string($_SESSION['fm_cwd']) || $_SESSION['fm_cwd'] === '') {
        $_SESSION['fm_cwd'] = $current_real;
    }
    $cwd = $_SESSION['fm_cwd'];

    // keep cwd inside base (safety)
    $cwd_real = realpath($cwd);
    if ($cwd_real === false) $cwd_real = $current_real;
    $realBase = rtrim($REAL_BASE, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    $cwdNorm = rtrim($cwd_real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if (strpos($cwdNorm, $realBase) !== 0) {
        $cwd_real = $current_real;
    }
    $cwd = $cwd_real;
    $_SESSION['fm_cwd'] = $cwd;

    // Block very dangerous commands
    $dangerous = array('rm -rf /', ':(){ :|:& };:', 'mkfs', 'dd if=/dev/random', '> /dev/sda', 'chmod -R 777 /', 'halt', 'shutdown');
    foreach ($dangerous as $d) {
        if (stripos($command, $d) !== false) {
            $out['msg'] = 'This command is blocked';
            header('Content-Type: application/json'); echo json_encode($out); exit;
        }
    }

    // Handle "cd" internally (persistent)
    if (preg_match('/^\s*cd(\s+(.+))?\s*$/', $command, $m)) {
        $arg = isset($m[2]) ? trim($m[2]) : '';
        if ($arg === '' || $arg === '~') {
            $target = $REAL_BASE;
        } else {
            // strip quotes
            if ((substr($arg, 0, 1) === '"' && substr($arg, -1) === '"') || (substr($arg, 0, 1) === "'" && substr($arg, -1) === "'")) {
                $arg = substr($arg, 1, -1);
            }

            if ($arg[0] === '/') {
                $target = $arg;
            } else {
                $target = rtrim($cwd, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $arg;
            }
        }

        $targetReal = realpath($target);
        if ($targetReal === false || !is_dir($targetReal)) {
            $out['ok'] = true;
            $out['output'] = "cd: no such file or directory: " . $arg;
            $out['code'] = 1;
            header('Content-Type: application/json'); echo json_encode($out); exit;
        }

        // enforce base dir
        $targetNorm = rtrim($targetReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (strpos($targetNorm, $realBase) !== 0) {
            $out['ok'] = true;
            $out['output'] = "cd: permission denied";
            $out['code'] = 1;
            header('Content-Type: application/json'); echo json_encode($out); exit;
        }

        $_SESSION['fm_cwd'] = rtrim($targetReal, DIRECTORY_SEPARATOR);
        $out['ok'] = true;
        $out['output'] = ""; // real terminals don't print anything on successful cd
        $out['code'] = 0;
        header('Content-Type: application/json'); echo json_encode($out); exit;
    }

    // run other commands in persistent cwd
    $fullCmd = 'cd ' . escapeshellarg($cwd) . ' && TERM=dumb ' . $command;

    $output = '';
    $return_var = 0;

    if (function_exists('proc_open')) {
        $descriptorspec = array(
            0 => array("pipe", "r"),
            1 => array("pipe", "w"),
            2 => array("pipe", "w")
        );
        $process = @proc_open($fullCmd, $descriptorspec, $pipes, $cwd);

        if (is_resource($process)) {
            @fclose($pipes[0]);
            $outt = stream_get_contents($pipes[1]); @fclose($pipes[1]);
            $err  = stream_get_contents($pipes[2]); @fclose($pipes[2]);
            $return_var = proc_close($process);
            $output = $outt . ($err ? "\n\nERROR:\n" . $err : '');
        } else {
            $output = "proc_open blocked or failed.";
        }
    } elseif (function_exists('shell_exec')) {
        $res = @shell_exec($fullCmd . ' 2>&1');
        $output = ($res === null) ? "shell_exec not available" : $res;
        $return_var = 0;
    } else {
        $output = "No execution functions available";
    }

    $_SESSION['cmd_output'] = $output;
    $_SESSION['cmd_return'] = $return_var;

    $out['ok'] = true;
    $out['msg'] = 'Executed';
    $out['output'] = $output;
    $out['code'] = intval($return_var);

    header('Content-Type: application/json');
    echo json_encode($out);
    exit;
}

/* ---------- HANDLE FORMS (upload/save/mkdir/newfile/rename) ---------- */
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_in = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    if (!check_csrf($csrf_in)) {
        http_response_code(400);
        echo "CSRF error!";
        exit;
    }
    $do = isset($_POST['do']) ? $_POST['do'] : '';

    if ($do === 'upload' && isset($_FILES['file'])) {
        $name = basename($_FILES['file']['name']);
        $target = $current_real . '/' . $name;
        if (is_uploaded_file($_FILES['file']['tmp_name']) && move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
            @chmod($target, 0644);
            $msg = "✅ $name uploaded";
        } else $msg = "❌ Upload failed";
    }

    if ($do === 'save' && isset($_POST['edit_path'])) {
        $real = realpath_in_base($_POST['edit_path']);
        if ($real && is_writable($real)) {
            $content = isset($_POST['content']) ? $_POST['content'] : '';
            if (strlen($content) < 5 * 1024 * 1024) {
                file_put_contents($real, $content);
                $msg = "✅ File saved";
            } else $msg = "❌ Content too big";
        } else $msg = "❌ Cannot write file";
    }

    if ($do === 'mkdir' && isset($_POST['folder'])) {
        $folder = basename($_POST['folder']);
        $path = $current_real . '/' . $folder;
        if ($folder === '') {
            $msg = "⚠️ Invalid folder name";
        } elseif (!file_exists($path)) {
            if (@mkdir($path, 0777, true)) $msg = "✅ Folder created"; else $msg = "❌ mkdir failed";
        } else $msg = "⚠️ Folder exists";
    }

    if ($do === 'newfile' && isset($_POST['folder'])) {
        $fname = basename($_POST['folder']);
        $target = $current_real . '/' . $fname;
        if ($fname === '') {
            $msg = "⚠️ Invalid file name";
        } elseif (file_exists($target)) {
            $msg = "⚠️ File already exists";
        } else {
            $ok = @file_put_contents($target, '');
            if ($ok !== false) {
                @chmod($target, 0644);
                $msg = "✅ File created: $fname";
            } else {
                $msg = "❌ File creation failed (permissions?)";
            }
        }
    }

    if ($do === 'rename' && isset($_POST['old']) && isset($_POST['new'])) {
    $oldParam = (string)$_POST['old'];
    $newParam = (string)$_POST['new'];

    $oldReal = realpath_in_base($oldParam);
    if ($oldReal === false || !file_exists($oldReal)) {
        $msg = "❌ Old missing";
        header('Location: ?dir=' . urlencode($current_rel) . '&msg=' . urlencode($msg));
        exit;
    }

    // yeni isim sadece aynı klasörde olsun (güvenli ve basit)
    $newBase = basename(str_replace(array("\0"), '', $newParam));
    if ($newBase === '' || $newBase === '.' || $newBase === '..') {
        $msg = "❌ Invalid new name";
        header('Location: ?dir=' . urlencode($current_rel) . '&msg=' . urlencode($msg));
        exit;
    }

    $newReal = dirname($oldReal) . DIRECTORY_SEPARATOR . $newBase;

    // base dışına taşmasın (paranoya)
    $realBase = rtrim($REAL_BASE, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    $newNorm = rtrim($newReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if (strpos($newNorm, $realBase) !== 0) {
        $msg = "❌ Invalid target";
        header('Location: ?dir=' . urlencode($current_rel) . '&msg=' . urlencode($msg));
        exit;
    }

    if (file_exists($newReal)) {
        $msg = "❌ New exists";
    } else {
        $msg = @rename($oldReal, $newReal) ? "✅ Renamed" : "❌ Rename failed";
    }

    header('Location: ?dir=' . urlencode($current_rel) . '&msg=' . urlencode($msg));
    exit;
}

/* ---------- TOPLU DOSYA İŞLEMLERİ ---------- */
if ($action === 'batch_operations' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $resp = array('ok' => false, 'results' => array(), 'error' => '');
    
    $csrf_in = isset($_POST['csrf']) ? $_POST['csrf'] : '';
    if (!check_csrf($csrf_in)) { $resp['error'] = 'CSRF error'; echo json_encode($resp); exit; }
    
    $operation = isset($_POST['operation']) ? $_POST['operation'] : '';
    $files = isset($_POST['files']) ? json_decode($_POST['files'], true) : array();
    $target = isset($_POST['target']) ? trim($_POST['target']) : '';
    
    if (empty($files)) { $resp['error'] = 'No files selected'; echo json_encode($resp); exit; }
    if (empty($operation)) { $resp['error'] = 'No operation specified'; echo json_encode($resp); exit; }
    
    $results = array();
    
    foreach ($files as $file) {
        $real = realpath_in_base($file);
        if ($real === false) {
            $results[$file] = array('success' => false, 'error' => 'Invalid path');
            continue;
        }
        
        $result = array('success' => false, 'error' => '');
        
        try {
            switch ($operation) {
                case 'delete':
                    if (is_dir($real)) {
                        $it = new RecursiveDirectoryIterator($real, RecursiveDirectoryIterator::SKIP_DOTS);
                        $files_it = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                        foreach ($files_it as $fileinfo) {
                            $fp = $fileinfo->getRealPath();
                            if ($fileinfo->isDir()) @rmdir($fp); else @unlink($fp);
                        }
                        $result['success'] = @rmdir($real);
                    } else {
                        $result['success'] = @unlink($real);
                    }
                    break;
                    
                case 'chmod_644':
                    $result['success'] = @chmod($real, 0644);
                    break;
                    
                case 'chmod_755':
                    $result['success'] = @chmod($real, 0755);
                    break;
                    
                case 'move':
                    if (empty($target)) {
                        $result['error'] = 'Target directory not specified';
                        break;
                    }
                    
                    $target_real = realpath_in_base($target);
                    if ($target_real === false || !is_dir($target_real)) {
                        $result['error'] = 'Target directory does not exist';
                        break;
                    }
                    
                    $new_path = $target_real . '/' . basename($real);
                    $result['success'] = @rename($real, $new_path);
                    break;
                    
                case 'copy':
                    if (empty($target)) {
                        $result['error'] = 'Target directory not specified';
                        break;
                    }
                    
                    $target_real = realpath_in_base($target);
                    if ($target_real === false || !is_dir($target_real)) {
                        $result['error'] = 'Target directory does not exist';
                        break;
                    }
                    
                    $new_path = $target_real . '/' . basename($real);
                    if (is_dir($real)) {
                        $result['success'] = copy_directory($real, $new_path);
                    } else {
                        $result['success'] = @copy($real, $new_path);
                    }
                    break;
                    
                case 'zip_selected':
                    if (strpos($zip_name, '/') !== false || strpos($zip_name, '\\') !== false) {
                      $result['error'] = 'Zip name must not contain path separators';
                      break;
                  }
                    // Seçili dosyaları zip yap
                    $zip_name = !empty($target) ? $target : 'batch_' . date('Ymd_His') . '.zip';
                    if (stripos($zip_name, '.zip') === false) $zip_name .= '.zip';
                    
                    $zip_path = $current_real . '/' . $zip_name;
                    $i = 1;
                    while (file_exists($zip_path)) {
                        $zip_path = $current_real . '/' . pathinfo($zip_name, PATHINFO_FILENAME) . '_' . $i . '.zip';
                        $i++;
                    }
                    
                    if (class_exists('ZipArchive')) {
                      $za = new ZipArchive();
                      $open = $za->open($realZip);

                      if ($open === true) {

                          for ($i = 0; $i < $za->numFiles; $i++) {
                            $stat = $za->statIndex($i);
                            if (!is_array($stat) || !isset($stat['name'])) continue;
                            $name = $stat['name'];

                            // normalize
                            $name = str_replace('\\', '/', $name);

                            // absolute path veya traversal yasak
                            if ($name === '' || $name[0] === '/' || strpos($name, '../') !== false || strpos($name, '..\\') !== false) {
                                $za->close();
                                $resp['error'] = 'Unsafe zip entry blocked: ' . $stat['name'];
                                header('Content-Type: application/json'); echo json_encode($resp); exit;
                            }
                        }

                          $res = $za->extractTo($extractTo);
                          $za->close();

                          if ($res) {
                              $resp['ok'] = true;
                              $resp['msg'] = 'Extracted to ' . $extractTo;
                              header('Content-Type: application/json'); echo json_encode($resp); exit;
                          } else {
                              $resp['error'] = 'extractTo failed';
                              header('Content-Type: application/json'); echo json_encode($resp); exit;
                          }

                      } else {
                          $resp['error'] = 'ZipArchive open failed: code ' . intval($open);
                          header('Content-Type: application/json'); echo json_encode($resp); exit;
                      }
                  }
                    break;
                    
                case 'touch':
                    $result['success'] = @touch($real);
                    break;
                    
                case 'empty_files':
                    if (is_file($real)) {
                        $result['success'] = (file_put_contents($real, '') !== false);
                    }
                    break;
                    
                case 'calculate_hash':
                    if (is_file($real)) {
                        $result['md5'] = md5_file($real);
                        $result['sha1'] = sha1_file($real);
                        $result['crc32'] = crc32(file_get_contents($real));
                        $result['success'] = true;
                    }
                    break;
            }
            
            if (!$result['success'] && empty($result['error'])) {
                $result['error'] = 'Operation failed (permissions?)';
            }
            
        } catch (Exception $e) {
            $result['error'] = $e->getMessage();
        }
        
        $results[$file] = $result;
    }
    
    $resp['ok'] = true;
    $resp['results'] = $results;
    echo json_encode($resp);
    exit;
}

/* ---------- YARDIMCI FONKSİYONLAR ---------- */
function copy_directory($src, $dst) {
    if (!is_dir($src)) return false;
    
    if (!is_dir($dst)) {
        if (!@mkdir($dst, 0777, true)) return false;
    }
    
    $dir = opendir($src);
    while (($file = readdir($dir)) !== false) {
        if ($file == '.' || $file == '..') continue;
        
        $src_file = $src . '/' . $file;
        $dst_file = $dst . '/' . $file;
        
        if (is_dir($src_file)) {
            if (!copy_directory($src_file, $dst_file)) return false;
        } else {
            if (!@copy($src_file, $dst_file)) return false;
        }
    }
    closedir($dir);
    return true;
}

/* ---------- GET: download/delete/load ---------- */
if ($action === 'download') {
    $file = isset($_GET['file']) ? realpath_in_base($_GET['file']) : false;
    if ($file && is_file($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        readfile($file);
        exit;
    }
        // NEW: folder download as zip
    $dirParam = isset($_GET['dir_dl']) ? $_GET['dir_dl'] : '';
    $realDir = $dirParam !== '' ? realpath_in_base($dirParam) : false;

    if ($realDir && is_dir($realDir)) {
        if (!class_exists('ZipArchive')) {
            http_response_code(500);
            echo "ZipArchive not available on server. Enable php-zip extension to download folders.";
            exit;
        }

        $zipPath = fm_temp_zip_path('fm_folder_', '.zip');
        if ($zipPath === false) {
            http_response_code(500);
            echo "Cannot create temp zip file.";
            exit;
        }

        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE) !== true) {
            http_response_code(500);
            echo "Cannot open temp zip for writing.";
            exit;
        }

        $baseName = basename($realDir);
        $zip->addEmptyDir($baseName);
        fm_zip_add_dir($zip, $realDir, $baseName);
        $zip->close();

        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $baseName . '.zip"');
        header('Content-Length: ' . filesize($zipPath));
        readfile($zipPath);
        @unlink($zipPath);
        exit;
    }
    http_response_code(404);
    echo "File/folder not found";
    exit;
    
}

if ($action === 'delete') {
    $targetParam = isset($_GET['target']) ? $_GET['target'] : '';
    $real = realpath_in_base($targetParam);
    if ($real === false) {
        $msg = "❌ Invalid path";
        header('Location: ?dir=' . urlencode($current_rel) . '&msg=' . urlencode($msg));
        exit;
    }

    if (file_exists($real)) {
        $deleted = false;
        if (is_dir($real)) {
            $it = new RecursiveDirectoryIterator($real, RecursiveDirectoryIterator::SKIP_DOTS);
            $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($files as $fileinfo) {
                $fp = $fileinfo->getRealPath();
                if ($fp === false) continue;
                if ($fileinfo->isDir()) @rmdir($fp); else @unlink($fp);
            }
            $deleted = @rmdir($real);
        } else {
            $deleted = @unlink($real);
        }
        $msg = $deleted ? "🗑️ Deleted: " . basename($real) : "❌ Delete failed";
    } else {
        $msg = "⚠️ Not found";
    }
    header('Location: ?dir=' . urlencode($current_rel) . '&msg=' . urlencode($msg));
    exit;
}

if ($action === 'load') {
    $file = isset($_GET['file']) ? realpath_in_base($_GET['file']) : false;
    if ($file && is_file($file) && is_readable($file)) {
        $mime = function_exists('mime_content_type') ? @mime_content_type($file) : 'application/octet-stream';
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $textext = array('php','txt','md','html','css','js','json','xml');
        if (strpos((string)$mime, 'text') === 0 || in_array($ext, $textext)) {
            header('Content-Type: text/plain; charset=utf-8');
            echo file_get_contents($file);
            exit;
        }
        http_response_code(400); echo "Not editable"; exit;
    }
    http_response_code(404); echo "Not found"; exit;
}

/* ---------- PREPARE DATA ---------- */
$items = is_dir($current_real) ? array_values(array_diff(scandir($current_real), array('.', '..'))) : array();
sort($items);

$cmd_output = isset($_SESSION['cmd_output']) ? $_SESSION['cmd_output'] : '';
$cmd_return = isset($_SESSION['cmd_return']) ? $_SESSION['cmd_return'] : 0;
unset($_SESSION['cmd_output'], $_SESSION['cmd_return']);
?>
<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TINYSHARK CO PANEL</title>
<link href="https://fonts.googleapis.com/css?family=Inter:300,400,600|JetBrains+Mono:400,700" rel="stylesheet">
<style>
:root{
  --bg:#041025; --panel:#07182a; --muted:#9fb0c8; --accent:#60a5fa; --danger:#ff6b6b; --success:#34d399;
  --glass: rgba(255,255,255,0.03); --scroll-thumb: rgba(255,255,255,0.08);
}
*{box-sizing:border-box}
html,body{height:100%;margin:0;font-family:Inter,Arial,Helvetica,sans-serif;background:linear-gradient(180deg,#041025 0%, #061a2d 100%);color:#e6eef6}
.container{width:100%;padding:20px 28px}
.header{display:flex;align-items:center;gap:12px;margin-bottom:14px;position:relative}
.brand h1{font-size:18px;margin:0}
.info{font-size:13px;color:var(--muted)}
.top-actions{margin-left:auto;display:flex;gap:8px;align-items:center}
.btn{background:var(--panel);border:1px solid rgba(255,255,255,0.04);color:var(--accent);padding:8px 12px;border-radius:8px;cursor:pointer}
.btn.ghost{background:transparent;color:var(--muted);border:1px solid rgba(255,255,255,0.02)}
.layout{display:grid;grid-template-columns:560px 1fr;gap:18px}
.sidebar{background:var(--panel);padding:14px;border-radius:12px;box-shadow:0 8px 30px rgba(2,6,23,.6);height:100%;overflow:hidden;position:relative}
.search-box{display:flex;gap:8px;align-items:center}
.search-box input{flex:1;padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:transparent;color:#e6eef6}
.search-hint{font-size:12px;color:var(--muted);margin-top:6px}
.folder-wrap{position:relative;height:calc(100% - 280px);overflow:hidden;border-radius:8px}
.folder-list{position:absolute;left:0;right:-20px;top:0;bottom:0;padding-right:20px;overflow:auto;-webkit-overflow-scrolling:touch}
.folder-list:before, .folder-list:after { content:''; position:sticky; pointer-events:none; left:0; right:0; height:36px; display:block; }
.folder-list:before { top:0; background:linear-gradient(180deg, rgba(4,16,28,0.9), rgba(4,16,28,0)); }
.folder-list:after { bottom:0; background:linear-gradient(180deg, rgba(4,16,28,0), rgba(4,16,28,0.9)); position:absolute; }
.file-card{background:var(--glass);padding:12px;border-radius:10px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;transition:transform .12s ease,box-shadow .12s ease;cursor:pointer}
.file-card:hover{transform:translateY(-3px);box-shadow:0 10px 30px rgba(2,6,23,.5)}
.file-meta{display:flex;flex-direction:column}
.file-meta .name{font-weight:600}
.file-meta .sub{color:var(--muted);font-size:13px;margin-top:4px}
.action-dots{display:flex;gap:8px;align-items:center}
.panel{background:var(--panel);padding:18px;border-radius:12px;box-shadow:0 8px 30px rgba(2,6,23,.6);min-height:520px}
.card-grid{display:grid;grid-template-columns:1fr;gap:16px} /* editor full width */
.form input,.form select,.form textarea{width:100%;padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:transparent;color:#e6eef6}
.form textarea{min-height:150px;font-family:JetBrains Mono,monospace}
.hint{font-size:13px;color:var(--muted);margin-top:8px}
.search-results{background:rgba(255,255,255,0.02);padding:10px;border-radius:8px;margin-bottom:12px;max-height:320px;overflow:auto}
.search-item{padding:8px;border-radius:6px;background:transparent;display:block;margin-bottom:6px}
.search-item:hover{background:rgba(255,255,255,0.02);cursor:pointer}
.terminal{background:#000;border-radius:8px;padding:12px;color:#d1ffd6;font-family:JetBrains Mono,monospace;font-size:13px;min-height:165px;max-height:520px;overflow:auto;border:1px solid rgba(255,255,255,0.04)}
.input-line{display:flex;gap:8px;margin-top:10px}
.term-input{flex:1;padding:10px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:#071017;color:#e6eef6;font-family:JetBrains Mono,monospace}
.context-menu{position:fixed;background:#071017;border:1px solid rgba(255,255,255,0.04);box-shadow:0 10px 30px rgba(2,6,23,.6);border-radius:8px;padding:6px;z-index:9999;min-width:220px;display:none}
.context-menu .item{padding:8px 10px;border-radius:6px;color:#e6eef6;cursor:pointer}
.context-menu .item:hover{background:rgba(255,255,255,0.02)}
.folder-list::-webkit-scrollbar{width:10px}
.folder-list::-webkit-scrollbar-track{background:transparent}
.folder-list::-webkit-scrollbar-thumb{background:var(--scroll-thumb);border-radius:999px;border:2px solid transparent;background-clip:padding-box}
@media(max-width:1100px){ .layout{grid-template-columns:420px 1fr} }
@media(max-width:900px){ .layout{grid-template-columns:1fr} .sidebar{height:auto} .folder-wrap{height:260px} }

/* --- Icons in sidebar --- */
.file-row{display:flex;align-items:center;gap:10px}
.file-ico{width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;
  border-radius:8px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.05);
  font-size:16px;flex:0 0 28px
}
.file-ico.small{font-size:15px}

/* Editor container: 240px */
#editor { height:240px; border-radius:8px; overflow:hidden; border:1px solid rgba(255,255,255,0.04); background:#0b1220; }

/* Select & option visibility fixes */
select { color: #e6eef6 !important; background: rgba(255,255,255,0.02) !important; -webkit-appearance: none; -moz-appearance: none; appearance: none; }
select option { color: #e6eef6 !important; background: #07182a !important; }

/* small IP pill */
.client-ip { color: var(--muted); font-size:13px; padding:8px 10px; border-radius:8px; border:1px solid rgba(255,255,255,0.03); background:transparent; display:inline-flex; align-items:center; }

/* header message centered */
.header-msg {
  position:absolute;
  left:50%;
  top:50%;
  transform:translate(-50%, -10%);
  background: rgba(96,165,250,0.06);
  color: var(--accent);
  padding:8px 14px;
  border-radius:8px;
  font-weight:600;
  display:inline-block;
  pointer-events:none;
}

/* --- Sidebar controls (match image1) --- */
.controls{
  display:flex;
  flex-direction:column;
  gap:10px;
  margin-top:12px;
}
.controls .row{ width:100%; }

/* Search row */
.controls .row.row-search .search-box{ width:100%; }
#globalSearch{ width:100% !important; }

/* Upload row */
.controls .row.row-upload form{
  width:100%;
  display:flex;
  align-items:center;
  gap:10px;
}
/* override generic .form input width:100% for toolbar rows */
.controls .row.row-upload input,
.controls .row.row-create input{
  width:auto;
}
#uploadFormInline input[type="file"]{
  flex:1 1 auto;
  min-width:240px;
  padding:8px;
  border-radius:8px;
  border:1px solid rgba(255,255,255,0.04);
  background: rgba(255,255,255,0.02);
  color:#e6eef6;
}
#uploadFormInline button{ flex:0 0 auto; white-space:nowrap; }

/* Create row */
.controls .row.row-create form{
  width:100%;
  display:flex;
  align-items:center;
  gap:10px;
}
#createName{
  flex:1 1 auto;
  min-width:240px;
  max-width:100%;
}
.controls .row.row-create button{
  flex:0 0 auto;
  white-space:nowrap;
}

/* responsive */
@media (max-width:700px){
  .controls .row.row-upload form,
  .controls .row.row-create form{ flex-wrap:wrap; }
  #uploadFormInline input[type="file"],
  #createName{ flex:1 1 100%; min-width:0; }
  #uploadFormInline button,
  .controls .row.row-create button{ flex:1 1 48%; }
}

/*TESSTTTTTTTTTTTTT */

/* Tab stilleri */
.tab-buttons {
    display: flex;
    gap: 5px;
    margin-bottom: 15px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    padding-bottom: 10px;
}
.tab-btn {
    padding: 8px 15px;
    background: transparent;
    border: none;
    color: var(--muted);
    cursor: pointer;
    border-radius: 6px;
}
.tab-btn.active {
    background: rgba(96,165,250,0.1);
    color: var(--accent);
}
.tab-content {
    display: none;
}
.tab-content.active {
    display: block;
    animation: fadeIn 0.3s;
}
@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

/* Veritabanı tablo listesi */
.db-table-list {
    max-height: 300px;
    overflow-y: auto;
    border: 1px solid rgba(255,255,255,0.05);
    border-radius: 8px;
    padding: 10px;
}
.db-table-item {
    padding: 8px 10px;
    border-radius: 6px;
    cursor: pointer;
    margin-bottom: 5px;
}
.db-table-item:hover {
    background: rgba(96,165,250,0.1);
}

/* Toplu işlemler listesi */
.selected-files-container {
    max-height: 200px;
    overflow-y: auto;
    background: rgba(0,0,0,0.2);
    border-radius: 8px;
    padding: 10px;
    margin: 10px 0;
}
.selected-file-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 5px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="brand">
      <h1>TINYSHARK CO PANEL</h1>
      <div class="info">User: <?php echo htmlspecialchars($_SESSION['fm_user']); ?> • PHP: <?php echo phpversion(); ?> • <?php echo htmlspecialchars($current_rel ? $current_rel : '/'); ?></div>
    </div>

    <?php if (!empty($_GET['msg'])): ?>
      <div class="header-msg" id="headerMsg"><?php echo htmlspecialchars($_GET['msg']); ?></div>
    <?php else: ?>
      <div class="header-msg" id="headerMsg" style="display:none"></div>
    <?php endif; ?>

    <div class="top-actions">
      <div class="client-ip" title="Client IP"><?php echo htmlspecialchars(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'Unknown'); ?></div>
      <a class="btn ghost" href="?">Home</a>
      <a class="btn" href="?action=logout">Logout</a>
    </div>
  </div>

  <div class="layout">
    <aside class="sidebar">

      <div class="controls">
        <!-- Search row (TOP) -->
        <div class="row row-search">
          <div class="search-box" style="width:100%;">
            <input id="globalSearch" placeholder="Dosya adı ara (Enter ile çalıştır)">
          </div>
        </div>

        <!-- Upload row (MIDDLE) -->
        <div class="row row-upload">
          <form id="uploadFormInline" method="post" enctype="multipart/form-data" class="form">
            <input type="hidden" name="csrf" value="<?php echo csrf_token(); ?>">
            <input type="hidden" name="do" value="upload">
            <input type="file" name="file" id="uploadFileInput" />
            <button class="btn" type="submit">Upload</button>
          </form>
        </div>

        <!-- Create row (BOTTOM) -->
        <div class="row row-create">
          <form id="createForm" method="post" class="form">
            <input type="hidden" name="csrf" value="<?php echo csrf_token(); ?>">
            <input type="text" name="folder" id="createName" placeholder="Yeni klasör / dosya adı" />
            <input type="hidden" name="do" value="mkdir" id="doField">
            <button type="button" class="btn" onclick="submitNew('mkdir')">New Folder</button>
            <button type="button" class="btn" onclick="submitNew('newfile')">New File</button>
          </form>
        </div>
      </div>

      <div class="search-hint">Enter tuşuna basınca dosya adlarında arar. Sağ tık -> "Text search..." ile dosya içlerinde arama yapabilirsiniz.</div>

      <div style="margin-top:12px" class="folder-wrap">
        <div class="folder-list" id="folderList">
          <?php if (!empty($current_rel)): ?>
          <div class="file-card" data-path="<?php echo htmlspecialchars(dirname($current_rel) == '.' ? '' : dirname($current_rel)); ?>" data-isdir="1">
            <div class="file-row">
              <span class="file-ico">📁</span>
              <div class="file-meta">
                <span class="name">.. (Parent)</span>
                <span class="sub">Klasör</span>
              </div>
            </div>
            <div class="action-dots"><button class="btn ghost" data-action="open">Open</button></div>
          </div>
          <?php endif; ?>

          <?php foreach ($items as $item):
            $path = $current_real . '/' . $item;
            $is_dir = is_dir($path) ? 1 : 0;
            $webpath = str_replace($_SERVER['DOCUMENT_ROOT'] ? $_SERVER['DOCUMENT_ROOT'] : '', '', $path);
            $perm = '';
            if (file_exists($path)) $perm = substr(sprintf('%o', fileperms($path)), -4);
            if ($is_dir) { $subLabel = 'Klasör' . ($perm ? ' • ' . $perm : ''); }
            else { $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION)); $size = is_readable($path) ? number_format(@filesize($path)).' bytes' : 'Unreadable'; $subLabel = 'Dosya' . ($ext ? ' • .' . $ext : '') . ' • ' . $size . ($perm ? ' • ' . $perm : ''); }
          ?>
          <div class="file-card" data-path="<?php echo htmlspecialchars($current_rel ? $current_rel . '/' . $item : $item); ?>" data-isdir="<?php echo $is_dir; ?>" data-perm="<?php echo htmlspecialchars($perm); ?>">
            <div class="file-row">
              <span class="file-ico"><?php echo htmlspecialchars(fm_icon_for($is_dir, $item)); ?></span>
              <div class="file-meta">
                <span class="name"><?php echo htmlspecialchars($item); ?></span>
                <span class="sub"><?php echo htmlspecialchars($subLabel); ?></span>
              </div>
            </div>
            <div class="action-dots">
              <?php if (!$is_dir): ?>
                <a class="btn ghost" href="<?php echo htmlspecialchars($webpath); ?>" target="_blank" data-action="view">View</a>
              <?php else: ?>
                <button class="btn ghost" data-action="open">Open</button>
              <?php endif; ?>
              <button class="btn" data-action="menu">•••</button>
            </div>
          </div>
          <?php endforeach; ?>
        </div>
      </div>
    </aside>

    <main>
      <div class="panel">
        <div style="margin-top: 20px;">
        <div style="display: flex; gap: 10px; margin-bottom: 15px;">
            <button class="btn ghost" onclick="showTab('files')">📁 Dosya Yöneticisi</button>
            <button class="btn ghost" onclick="showTab('search')">🔍 Gelişmiş Arama</button>
            <button class="btn ghost" onclick="showTab('database')">🗃️ Veritabanı</button>
            <button class="btn ghost" onclick="showTab('batch')">🔄 Toplu İşlemler</button>
        </div>
        
        <!-- Dosya Yöneticisi (mevcut içerik) -->
        <div id="tab-files" class="tab-content">
            <!-- Mevcut dosya listesi burada kalacak -->
        </div>
        
        <!-- Gelişmiş Arama -->
        <div id="tab-search" class="tab-content" style="display:none;">
            <div class="panel" style="padding: 20px;">
                <h3>🔍 Gelişmiş Dosya Arama</h3>
                <form id="advancedSearchForm" class="form">
                    <input type="hidden" name="csrf" value="<?php echo csrf_token(); ?>">
                    
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                        <div>
                            <label>Dosya Adı</label>
                            <input type="text" name="name_query" placeholder="Dosya adında ara...">
                        </div>
                        <div>
                            <label>İçerik</label>
                            <input type="text" name="content_query" placeholder="Dosya içeriğinde ara...">
                        </div>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 15px;">
                        <div>
                            <label>Min Boyut (KB)</label>
                            <input type="number" name="size_min" placeholder="0" style="width:100%">
                        </div>
                        <div>
                            <label>Max Boyut (KB)</label>
                            <input type="number" name="size_max" placeholder="10240" style="width:100%">
                        </div>
                        <div>
                            <label>Tarih (Başlangıç)</label>
                            <input type="date" name="date_from" style="width:100%">
                        </div>
                        <div>
                            <label>Tarih (Bitiş)</label>
                            <input type="date" name="date_to" style="width:100%">
                        </div>
                    </div>
                    
                    <div style="display: flex; gap: 15px; margin-bottom: 15px; align-items: center;">
                        <div style="flex:1">
                            <label>Uzantılar (virgülle ayır)</label>
                            <input type="text" name="extensions" placeholder="php,html,js,css" style="width:100%">
                        </div>
                        <div>
                            <label style="display:block">
                                <input type="checkbox" name="case_sensitive" style="margin-right:5px">
                                Büyük/küçük harf duyarlı
                            </label>
                            <label style="display:block">
                                <input type="checkbox" name="use_regex" style="margin-right:5px">
                                Regex kullan
                            </label>
                        </div>
                        <div>
                            <label>Maksimum Sonuç</label>
                            <select name="max_results" style="width:100%">
                                <option value="100">100</option>
                                <option value="500" selected>500</option>
                                <option value="1000">1000</option>
                                <option value="5000">5000</option>
                            </select>
                        </div>
                    </div>
                    
                    <button type="button" class="btn" onclick="runAdvancedSearch()">🔍 Ara</button>
                    <button type="button" class="btn ghost" onclick="clearSearch()">Temizle</button>
                </form>
                
                <div id="searchResults" style="margin-top:20px; max-height:400px; overflow:auto;"></div>
            </div>
        </div>
        
        <!-- Veritabanı Yönetimi -->
        <div id="tab-database" class="tab-content" style="display:none;">
            <div class="panel" style="padding: 20px;">
                <h3>🗃️ Veritabanı Yönetimi</h3>
                
                <!-- Bağlantı Formu -->
                <div id="dbConnectForm">
                    <h4>Bağlantı Ayarları</h4>
                    <form id="dbConnectFormInner" class="form" style="display:grid; grid-template-columns: repeat(3, 1fr); gap:10px;">
                        <input type="hidden" name="csrf" value="<?php echo csrf_token(); ?>">
                        <select name="type" style="grid-column: span 3;">
                            <option value="mysql">MySQL</option>
                            <option value="postgresql">PostgreSQL</option>
                        </select>
                        <input type="text" name="host" placeholder="Host" value="localhost">
                        <input type="number" name="port" placeholder="Port" value="3306">
                        <input type="text" name="user" placeholder="Kullanıcı">
                        <input type="password" name="pass" placeholder="Şifre">
                        <input type="text" name="dbname" placeholder="Veritabanı Adı">
                        <button type="button" class="btn" onclick="dbConnect()" style="grid-column: span 3;">Bağlan</button>
                    </form>
                </div>
                
                <!-- Bağlı Durum -->
                <div id="dbConnected" style="display:none;">
                    <div style="background: rgba(52, 211, 153, 0.1); padding: 10px; border-radius: 8px; margin-bottom: 15px;">
                        <span id="dbStatusText"></span>
                        <button class="btn ghost" onclick="dbDisconnect()" style="float:right">Bağlantıyı Kes</button>
                    </div>
                    
                    <div style="display: grid; grid-template-columns: 250px 1fr; gap: 20px;">
                        <!-- Tablo Listesi -->
                        <div>
                            <h4>Tablo Listesi</h4>
                            <div id="dbTables" style="max-height:300px; overflow:auto;"></div>
                        </div>
                        
                        <!-- Sorgu Çalıştırma -->
                        <div>
                            <h4>SQL Sorgusu</h4>
                            <textarea id="dbQuery" rows="6" style="width:100%; font-family: monospace;" placeholder="SELECT * FROM users LIMIT 10"></textarea>
                            <button class="btn" onclick="dbRunQuery()">Çalıştır</button>
                            <button class="btn ghost" onclick="loadTables()">Tabloları Yenile</button>
                            
                            <div id="dbResults" style="margin-top:15px; max-height:300px; overflow:auto;"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Toplu İşlemler -->
        <div id="tab-batch" class="tab-content" style="display:none;">
            <div class="panel" style="padding: 20px;">
                <h3>🔄 Toplu Dosya İşlemleri</h3>
                
                <div style="margin-bottom: 15px;">
                    <label>İşlem:</label>
                    <select id="batchOperation" style="width:200px; margin-right:10px;">
                        <option value="delete">Sil</option>
                        <option value="chmod_644">CHMOD 644</option>
                        <option value="chmod_755">CHMOD 755</option>
                        <option value="move">Taşı</option>
                        <option value="copy">Kopyala</option>
                        <option value="zip_selected">ZIP Yap</option>
                        <option value="touch">Tarih Güncelle</option>
                        <option value="empty_files">İçeriği Temizle</option>
                        <option value="calculate_hash">Hash Hesapla</option>
                    </select>
                    
                    <div id="batchTargetContainer" style="display:none; margin-top:10px;">
                        <label>Hedef Dizin/Zip Adı:</label>
                        <input type="text" id="batchTarget" placeholder="/path/to/target veya filename.zip" style="width:300px;">
                    </div>
                </div>
                
                <div style="background: rgba(255,255,255,0.03); padding:15px; border-radius:8px; max-height:300px; overflow:auto;">
                    <h4>Seçili Dosyalar</h4>
                    <div id="selectedFilesList"></div>
                </div>
                
                <button class="btn" onclick="runBatchOperation()" style="margin-top:15px;">İşlemi Çalıştır</button>
                <button class="btn ghost" onclick="clearSelection()">Seçimi Temizle</button>
                
                <div id="batchResults" style="margin-top:15px;"></div>
            </div>
        </div>
    </div>

    <style>
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    .file-checkbox { margin-right: 10px; }
    .db-table-item { padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.05); cursor: pointer; }
    .db-table-item:hover { background: rgba(255,255,255,0.02); }
    </style>
        <div id="searchResultsContainer" class="search-results" style="display:none"></div>

        <div class="card-grid">
          <div>
            <form method="post" id="editForm" class="form">
              <input type="hidden" name="csrf" value="<?php echo csrf_token(); ?>">
              <input type="hidden" name="do" value="save">
              <label style="font-size:13px;color:var(--muted)">Dosya seç</label>
              <select name="edit_path" id="editSelect" onchange="onEditSelectChange(this.value)">
                <option value="">-- Dosya seç --</option>
                <?php foreach ($items as $item): if (!is_dir($current_real . '/' . $item)): ?>
                <option value="<?php echo htmlspecialchars($current_rel ? $current_rel . '/' . $item : $item); ?>"><?php echo htmlspecialchars($item); ?></option>
                <?php endif; endforeach; ?>
              </select>

              <div style="margin-top:8px">
                <div id="editor" aria-label="Code editor (Monaco)"></div>
                <textarea id="editContent" name="content" style="display:none"></textarea>
              </div>

              <div style="margin-top:8px">
                <button class="btn" type="submit" id="saveBtn">💾 Kaydet</button>
                <span style="margin-left:12px;font-size:13px;color:var(--muted)">Kısayollar: Ctrl+F (find), Ctrl+S (kaydet)</span>
              </div>
            </form>
          </div>
        </div>

        <hr style="border:none;border-top:1px solid rgba(255,255,255,0.03);margin:18px 0">

        <div id="terminal" class="terminal" aria-live="polite">
          <div class="meta">Working dir: <span class="badge"><?php echo htmlspecialchars(isset($_SESSION['fm_cwd']) ? $_SESSION['fm_cwd'] : $current_real); ?></span></div>
        </div>

        <div class="input-line">
          <input id="termInput" class="term-input" placeholder="Örn: ls -la, pwd, whoami" autocomplete="off">
          <button id="termSend" class="btn">Çalıştır</button>
        </div>

        <div style="margin-top:12px;color:var(--muted)">Terminal runs via AJAX</div>

        <div style="margin-top:12px;font-size:13px;color:var(--muted);line-height:1.5">
          <strong>Sunucu:</strong> <?php echo htmlspecialchars(php_uname()); ?><br>
          <strong>PHP:</strong> <?php echo phpversion(); ?><br>
          <strong>Çalışma Dizin:</strong> <?php echo htmlspecialchars($current_real); ?><br>
          <div class="hint">Not: Komut çalıştırma host tarafından kısıtlanmış olabilir. Terminal bölümünü kullanarak test edebilirsiniz.</div>
        </div>

        <div class="footer" style="margin-top:12px;color:var(--muted)"><div>Tips: Right-click for context menu (extract, archive, chmod, rename, delete, text search).</div></div>
      </div>
    </main>
  </div>
</div>

<div id="contextMenu" class="context-menu" role="menu">
  <div class="item" data-cmd="goto">Dosyaya Git</div>
  <div class="item" data-cmd="open">Open</div>
  <div class="item" data-cmd="download">Download</div>
  <div class="item" data-cmd="edit">Edit</div>
  <div class="item" data-cmd="rename">Rename</div>
  <div class="item" data-cmd="chmod">İzin Değiştir</div>
  <div class="item" data-cmd="extract_here">Buraya Çıkar</div>
  <div class="item" data-cmd="extract_to">Klasöre Çıkar</div>
  <div class="item" data-cmd="archive">Arşivle</div>
  <div class="item" data-cmd="text_search">Text search...</div>
  <div class="item" data-cmd="delete">Delete</div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs/loader.min.js"></script>

<script>
(function(){
  function qs(sel, root){ return (root||document).querySelector(sel); }
  function qsa(sel, root){ return Array.prototype.slice.call((root||document).querySelectorAll(sel)); }
  function ajax(url, method, data, cb) {
    var xhr = new XMLHttpRequest();
    xhr.open(method, url, true);
    xhr.onreadystatechange = function(){ if (xhr.readyState === 4) cb(xhr.status, xhr.responseText); };
    xhr.send(data || null);
  }

  var folderList = qs('#folderList');
  var context = qs('#contextMenu');
  var lastTarget = null;
  var searchBox = qs('#globalSearch');
  var resultsContainer = qs('#searchResultsContainer');

  var monacoEditor = null;
  var monacoLoaded = false;

  var extLang = {
    'php':'php','js':'javascript','ts':'typescript','css':'css','scss':'scss','less':'less','html':'html','htm':'html','json':'json',
    'py':'python','sh':'shell','bash':'shell','zsh':'shell','sql':'sql','md':'markdown','markdown':'markdown','txt':'plaintext',
    'xml':'xml','java':'java','c':'c','cpp':'cpp','h':'cpp','cs':'csharp','go':'go','rb':'ruby','rs':'rust','swift':'swift'
  };

  if (typeof require === 'function' && typeof require.config === 'function') {
    try {
      require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs' }});
      require(['vs/editor/editor.main'], function() {
        monacoLoaded = true;
        monacoEditor = monaco.editor.create(document.getElementById('editor'), {
          value: '',
          language: 'plaintext',
          theme: 'vs-dark',
          automaticLayout: true,
          minimap: { enabled: false },
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: 13,
          readOnly: true
        });

        monacoEditor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KEY_S, function() {
          var ta = document.getElementById('editContent');
          if (ta) ta.value = monacoEditor.getValue();
          var form = document.getElementById('editForm');
          if (form) form.submit();
        });
      });
    } catch (e) {
      console.warn('Monaco require init failed', e);
      monacoLoaded = false;
    }
  } else {
    console.warn('Require not available for Monaco loader.');
  }

  window.submitNew = function(kind) {
    var form = document.getElementById('createForm');
    var doField = document.getElementById('doField');
    var nameInput = document.getElementById('createName');
    if (!form || !doField || !nameInput) { alert('Form veya alan bulunamadı'); return; }
    var v = nameInput.value.trim();
    if (!v) { alert('Lütfen isim girin'); nameInput.focus(); return; }
    if (kind === 'newfile') doField.value = 'newfile'; else doField.value = 'mkdir';
    form.submit();
  };

  if (searchBox) {
    searchBox.addEventListener('keydown', function(e){
      if (e.keyCode === 13) {
        e.preventDefault();
        var q = searchBox.value.trim();
        if (!q) { resultsContainer.style.display='none'; return; }
        ajax('?action=search&type=name&q=' + encodeURIComponent(q), 'GET', null, function(status, resp){
          if (status === 200) {
            try { var res = JSON.parse(resp); if (res.ok) renderSearchResults(res.results); else alert('Search error: ' + (res.error||'unknown')); } catch (e) { alert('Unexpected response'); }
          } else alert('Search failed: HTTP ' + status);
        });
      }
    });
  }

  function renderSearchResults(results) {
    if (!results || !results.length) { resultsContainer.style.display = 'block'; resultsContainer.innerHTML = '<div style="color:var(--muted)">No results</div>'; return; }
    var html = '';
    for (var i=0;i<results.length;i++) {
      var r = results[i];
      var snippet = r.snippet ? '<div style="color:var(--muted);font-size:13px;margin-top:6px;">' + escapeHtml(r.snippet) + '</div>' : '';
      html += '<div class="search-item" data-path="'+escapeHtml(r.path)+'" data-isdir="'+(r.is_dir?1:0)+'"><strong>'+escapeHtml(r.path)+'</strong> <div style="color:var(--muted);font-size:12px;">'+escapeHtml(r.matchType)+'</div>'+snippet+'</div>';
    }
    resultsContainer.style.display = 'block';
    resultsContainer.innerHTML = html;
    qsa('.search-item').forEach(function(node){
      node.addEventListener('click', function(){
        var p = node.getAttribute('data-path');
        var isd = node.getAttribute('data-isdir') === '1';
        if (isd) window.location = '?dir=' + encodeURIComponent(p);
        else editFile(p);
      }, false);
    });
  }
  function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  document.addEventListener('contextmenu', function(e){
    var card = e.target;
    while (card && !card.classList.contains('file-card')) card = card.parentNode;
    if (card && folderList.contains(card)) {
      e.preventDefault();
      showContextMenu(card, e.clientX, e.clientY);
      return false;
    }
  }, false);

  folderList.addEventListener('click', function(e){
    var target = e.target;
    if (target.closest && target.closest('form')) return;
    var card = target;
    while (card && !card.classList.contains('file-card')) card = card.parentNode;
    if (!card) return;

    var menuBtn = target.getAttribute && target.getAttribute('data-action') === 'menu';
    if (menuBtn) { var rect = target.getBoundingClientRect(); showContextMenu(card, rect.left, rect.bottom); return; }

    var openBtn = target.getAttribute && target.getAttribute('data-action') === 'open';
    if (openBtn) { openItem(card); return; }

    if (target.tagName === 'A' || (target.closest && target.closest('a'))) return;

    openItem(card);
  }, false);

  document.addEventListener('click', function(e){ if (context.style.display === 'block') context.style.display = 'none'; }, false);

  function showContextMenu(card, x, y) {
    lastTarget = card;
    var isDir = card.getAttribute('data-isdir') === '1';
    var path = card.getAttribute('data-path') || '';
    var isZip = !isDir && path.toLowerCase().slice(-4) === '.zip';
    qsa('#contextMenu .item').forEach(function(it){
      var cmd = it.getAttribute('data-cmd');
      it.style.display = 'block';
      //if (cmd === 'download' && isDir) it.style.display = 'none';
      if (cmd === 'edit' && isDir) it.style.display = 'none';
      if ((cmd === 'extract_here' || cmd === 'extract_to') && !isZip) it.style.display = 'none';
      if (cmd === 'archive' && !isDir) it.style.display = 'none';
    });
    context.style.left = (x + 6) + 'px';
    context.style.top = (y + 6) + 'px';
    context.style.display = 'block';
  }

  context.addEventListener('click', function(e){
    var item = e.target;
    if (!item.classList.contains('item')) return;
    var cmd = item.getAttribute('data-cmd');
    if (!lastTarget) return;
    var path = lastTarget.getAttribute('data-path');
    var isDir = lastTarget.getAttribute('data-isdir') === '1';
    var curPerm = lastTarget.getAttribute('data-perm') || '';
    context.style.display = 'none';
    switch (cmd) {
      case 'goto': if (isDir) window.location = '?dir=' + encodeURIComponent(path); else window.open(path,'_blank'); break;
      case 'open': if (isDir) window.location = '?dir=' + encodeURIComponent(path); else window.open(path,'_blank'); break;
      case 'download':
        if (isDir) window.location = '?action=download&dir_dl=' + encodeURIComponent(path);
        else window.location = '?action=download&file=' + encodeURIComponent(path);
        break;
      case 'edit': editFile(path); break;
      case 'rename':
        var newName = prompt('Yeni isim:', path);
        if (newName) {
          var fd = new FormData();
          fd.append('csrf','<?php echo csrf_token(); ?>');
          fd.append('do','rename');
          fd.append('old',path);
          fd.append('new',newName);
          ajax('', 'POST', fd, function(s,r){ if (s===200) window.location.reload(); else alert('Rename failed'); });
        }
        break;
      case 'chmod':
        var hint = curPerm ? curPerm : '0644';
        var mode = prompt('İzin (octal, ör: 644 veya 0755):', hint);
        if (mode !== null && mode !== '') {
          mode = mode.replace(/[^0-7]/g,'');
          if (!/^[0-7]{3,4}$/.test(mode)) { alert('Geçersiz izin formatı. Ör: 644 veya 0755'); break; }
          var fd2 = new FormData();
          fd2.append('csrf','<?php echo csrf_token(); ?>');
          fd2.append('path', path);
          fd2.append('mode', mode);
          ajax('?action=chmod', 'POST', fd2, function(status, resp){
            try {
              var res = JSON.parse(resp);
              if (status===200 && res.ok) {
                alert('Başarılı: ' + res.msg);
                lastTarget.setAttribute('data-perm', (mode.length===3?('0'+mode):mode));
                var sub = lastTarget.querySelector('.sub');
                if (sub) {
                  var text = sub.textContent;
                  if (text.match(/ • [0-7]{3,4}$/)) sub.textContent = text.replace(/ • [0-7]{3,4}$/, ' • ' + (mode.length===3?('0'+mode):mode));
                  else sub.textContent = text + ' • ' + (mode.length===3?('0'+mode):mode);
                }
              } else {
                alert('İzin değiştirilemedi: ' + (res.error || resp));
              }
            } catch (e) { alert('Unexpected response: ' + resp); }
          });
        }
        break;
      case 'extract_here':
        if (!confirm('Zip dosyasını bu dizine çıkarmak istiyor musunuz?')) break;
        var fd3 = new FormData(); fd3.append('csrf','<?php echo csrf_token(); ?>'); fd3.append('path', path);
        ajax('?action=zip_extract', 'POST', fd3, function(status, resp){ try { var res = JSON.parse(resp); if (status===200 && res.ok) { alert('Çıkarıldı: ' + res.msg); window.location.reload(); } else alert('Extract failed: ' + (res.error || resp)); } catch (e) { alert('Unexpected response'); } });
        break;
      case 'extract_to':
        var folder = prompt('Hedef klasör adı (yoksa oluşturulur):', '');
        if (folder === null) break;
        folder = folder.trim();
        if (folder === '') { alert('Geçersiz klasör adı'); break; }
        var fd4 = new FormData(); fd4.append('csrf','<?php echo csrf_token(); ?>'); fd4.append('path', path); fd4.append('target', folder);
        ajax('?action=zip_extract', 'POST', fd4, function(status, resp){ try { var res = JSON.parse(resp); if (status===200 && res.ok) { alert('Çıkarıldı: ' + res.msg); window.location.reload(); } else alert('Extract failed: ' + (res.error || resp)); } catch (e) { alert('Unexpected response'); } });
        break;
      case 'archive':
        var name = prompt('Oluşturulacak ZIP dosya adı (uzantı yazmayın veya yazabilirsiniz):', '');
        if (name === null) break;
        name = name.trim();
        var fd5 = new FormData(); fd5.append('csrf','<?php echo csrf_token(); ?>'); fd5.append('path', path); fd5.append('name', name);
        ajax('?action=zip_archive', 'POST', fd5, function(status, resp){ try { var res = JSON.parse(resp); if (status===200 && res.ok) { alert('Arşiv oluşturuldu: ' + res.msg); window.location.reload(); } else alert('Archive failed: ' + (res.error || resp) + (res.out ? ("\n\n" + res.out) : '')); } catch (e) { alert('Unexpected response'); } });
        break;
      case 'text_search':
        var q = prompt('Dosya içlerinde ara (örnek: TODO):','');
        if (q !== null && q !== '') {
          ajax('?action=search&type=content&q=' + encodeURIComponent(q), 'GET', null, function(status, resp){
            if (status === 200) {
              try { var res = JSON.parse(resp); if (res.ok) renderSearchResults(res.results); else alert('Search error: ' + (res.error||'unknown')); } catch (e) { alert('Unexpected response'); }
            } else alert('Search failed: HTTP ' + status);
          });
        }
        break;
      case 'delete':
        if (confirm('Delete ' + path + '? This is irreversible.')) {
          window.location = '?action=delete&target=' + encodeURIComponent(path) + '&dir=' + encodeURIComponent('<?php echo $current_rel; ?>');
        }
        break;
    }
  }, false);

  function openItem(card) {
    qsa('.file-card.selected').forEach(function(n){ n.classList.remove('selected'); n.style.boxShadow=''; });
    card.classList.add('selected'); card.style.boxShadow = '0 12px 30px rgba(2,6,23,.6)';
    var path = card.getAttribute('data-path'); var isDir = card.getAttribute('data-isdir') === '1';
    if (isDir) window.location = '?dir=' + encodeURIComponent(path);
    else { editFile(path); setTimeout(function(){ if (monacoEditor) monacoEditor.focus(); }, 200); }
  }

  window.editFile = function(path){
    var sel = document.querySelector('[name="edit_path"]');
    if (!sel) return;
    var found = false;
    for (var i=0;i<sel.options.length;i++) {
      if (sel.options[i].value === path) { sel.selectedIndex = i; found = true; break; }
    }
    if (!found) {
      var opt = document.createElement('option'); opt.value = path; opt.text = path; sel.appendChild(opt); sel.value = path;
    }
    onEditSelectChange(path);
  };

  function setEditorEnabled(enabled) {
    var ta = document.getElementById('editContent');
    var saveBtn = document.getElementById('saveBtn');
    var select = document.getElementById('editSelect');
    if (ta) ta.disabled = !enabled;
    if (saveBtn) saveBtn.disabled = !enabled;
    if (select) {
      if (!enabled) select.classList.add('disabled');
      else select.classList.remove('disabled');
    }
    if (monacoLoaded && monacoEditor) {
      monacoEditor.updateOptions({ readOnly: !enabled });
      if (!enabled) monacoEditor.setValue('');
    } else {
      if (!enabled && ta) ta.value = '';
    }
  }

  window.onEditSelectChange = function(value) {
    if (!value) {
      setEditorEnabled(false);
      return;
    }
    loadFile(value);
  };

  window.loadFile = function(path){
    if (!path) { setEditorEnabled(false); return; }
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '?action=load&file=' + encodeURIComponent(path), true);
    xhr.onreadystatechange = function(){
      if (xhr.readyState !== 4) return;
      var ta = document.getElementById('editContent');
      if (xhr.status === 200) {
        var content = xhr.responseText;
        if (monacoLoaded && monacoEditor) {
          monacoEditor.setValue(content);
          var ext = (path.split('.').pop() || '').toLowerCase();
          var lang = extLang[ext] || 'plaintext';
          try { monaco.editor.setModelLanguage(monacoEditor.getModel(), lang); } catch (e) {}
        } else if (ta) {
          ta.value = content;
        }
        setEditorEnabled(true);
      } else {
        if (ta) ta.value = 'Error: ' + xhr.responseText;
        setEditorEnabled(false);
      }
    };
    xhr.send();
  };

  var editForm = document.getElementById('editForm');
  if (editForm) {
    editForm.addEventListener('submit', function(e){
      var ta = document.getElementById('editContent');
      if (monacoLoaded && monacoEditor && ta) {
        ta.value = monacoEditor.getValue();
      }
    }, false);
  }

  var term = qs('#terminal');
  var termInput = qs('#termInput');
  var termBtn = qs('#termSend');

  function appendLine(text, cls) {
    var div = document.createElement('div');
    div.className = 'line' + (cls ? ' ' + cls : '');
    div.textContent = text;
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
  }
  function appendOutput(command, output, code) {
    appendLine('> ' + command);
    if (!output) appendLine('(no output)');
    else {
      var lines = output.replace(/\r/g,'').split('\n');
      for (var i=0;i<lines.length;i++) appendLine(lines[i]);
    }
    appendLine('exit code: ' + (code||0), 'meta');
  }

  termBtn.addEventListener('click', function(){
    var cmd = termInput.value.trim();
    if (!cmd) return;
    appendLine('⏳ ' + cmd + ' (running...)', 'meta');
    var fd = new FormData();
    fd.append('csrf', '<?php echo csrf_token(); ?>');
    fd.append('command', cmd);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '?action=ajax_cmd', true);
    xhr.onreadystatechange = function() {
      if (xhr.readyState !== 4) return;
      var metas = term.querySelectorAll('.meta');
      if (metas.length) {
        var last = metas[metas.length-1];
        if (last && last.textContent.indexOf('(running...)') !== -1) last.parentNode.removeChild(last);
      }
      if (xhr.status === 200) {
        try {
          var res = JSON.parse(xhr.responseText);
          if (res.ok) appendOutput(cmd, res.output || '', res.code); else appendLine('Error: ' + (res.msg || 'unknown'), 'error');
        } catch (e) {
          appendLine('Unexpected response: ' + xhr.responseText, 'error');
        }
      } else appendLine('Server error: HTTP ' + xhr.status, 'error');
    };
    xhr.send(fd);
    termInput.value = '';
  }, false);

  termInput.addEventListener('keydown', function(e){ if (e.keyCode === 13) { e.preventDefault(); termBtn.click(); } });
  document.addEventListener('keydown', function(e){ if (e.keyCode === 27) context.style.display = 'none'; }, false);
  var fl = qs('.folder-list'); if (fl) fl.style.scrollBehavior = 'smooth';

  var touchTimer = null;
  folderList.addEventListener('touchstart', function(e){
    var t = e.target;
    while (t && !t.classList.contains('file-card')) t = t.parentNode;
    if (!t) return;
    touchTimer = setTimeout(function(){ showContextMenu(t, (window.innerWidth/2), (window.innerHeight/2)); }, 700);
  }, false);
  folderList.addEventListener('touchend', function(){ if (touchTimer) clearTimeout(touchTimer); }, false);

  document.addEventListener('click', function(e){
    var r = qs('#searchResultsContainer');
    if (!r) return;
    if (!r.contains(e.target) && e.target !== searchBox) r.style.display = 'none';
  }, false);

  document.addEventListener('DOMContentLoaded', function(){
    var sel = document.getElementById('editSelect');
    if (!sel || !sel.value) setEditorEnabled(false);
    else setEditorEnabled(true);

    var headerMsg = document.getElementById('headerMsg');
    if (headerMsg && headerMsg.textContent.trim() === '') headerMsg.style.display = 'none';
    if (headerMsg && headerMsg.textContent.trim() !== '') {
      setTimeout(function(){ headerMsg.style.transition='opacity 0.6s'; headerMsg.style.opacity='0.9'; }, 100);
      setTimeout(function(){ headerMsg.style.opacity='0.6'; }, 6000);
    }
  });

  <?php if ($cmd_output !== ''): ?>
  (function(){
    var out = <?php echo json_encode((string)$cmd_output); ?>;
    var code = <?php echo intval($cmd_return); ?>;
    appendOutput('previous-server-cmd', out, code);
  })();
  <?php endif; ?>

})();
/* ---------- TAB YÖNETİMİ ---------- */
function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(function(tab) {
        tab.style.display = 'none';
        tab.classList.remove('active');
    });
    document.querySelectorAll('.btn.ghost').forEach(function(btn) {
        btn.style.background = 'transparent';
    });
    
    var tab = document.getElementById('tab-' + tabName);
    if (tab) {
        tab.style.display = 'block';
        tab.classList.add('active');
    }
}

// Sayfa yüklendiğinde dosya sekmesini göster
window.addEventListener('DOMContentLoaded', function() {
    showTab('files');
});

/* ---------- GELİŞMİŞ ARAMA ---------- */
function runAdvancedSearch() {
    var form = document.getElementById('advancedSearchForm');
    var formData = new FormData(form);
    formData.append('search_type', 'advanced');
    
    var resultsDiv = document.getElementById('searchResults');
    resultsDiv.innerHTML = '<div style="color:var(--muted)">Arama yapılıyor...</div>';
    
    ajax('?action=advanced_search', 'POST', formData, function(status, resp) {
        try {
            var res = JSON.parse(resp);
            if (res.ok) {
                var html = '<h4>Sonuçlar: ' + res.count + ' dosya</h4>';
                if (res.results.length > 0) {
                    html += '<table style="width:100%; border-collapse:collapse;">';
                    html += '<tr><th>Dosya</th><th>Boyut</th><th>Değişti</th><th>İzinler</th><th>İşlem</th></tr>';
                    
                    res.results.forEach(function(item) {
                        html += '<tr>';
                        html += '<td>' + escapeHtml(item.path) + '</td>';
                        html += '<td>' + formatBytes(item.size) + '</td>';
                        html += '<td>' + item.modified + '</td>';
                        html += '<td>' + item.perms + '</td>';
                        html += '<td><button class="btn ghost" onclick="editFile(\'' + escapeHtml(item.path) + '\')">Düzenle</button></td>';
                        html += '</tr>';
                    });
                    
                    html += '</table>';
                } else {
                    html += '<div style="color:var(--muted)">Sonuç bulunamadı</div>';
                }
                resultsDiv.innerHTML = html;
            } else {
                resultsDiv.innerHTML = '<div style="color:var(--danger)">Hata: ' + escapeHtml(res.error) + '</div>';
            }
        } catch (e) {
            resultsDiv.innerHTML = '<div style="color:var(--danger)">Beklenmeyen yanıt</div>';
        }
    });
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    var k = 1024;
    var sizes = ['B', 'KB', 'MB', 'GB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/* ---------- VERİTABANI YÖNETİMİ ---------- */
function dbConnect() {
    var form = document.getElementById('dbConnectFormInner');
    var formData = new FormData(form);
    
    ajax('?action=db_connect', 'POST', formData, function(status, resp) {
        try {
            var res = JSON.parse(resp);
            if (res.ok) {
                document.getElementById('dbConnectForm').style.display = 'none';
                document.getElementById('dbConnected').style.display = 'block';
                document.getElementById('dbStatusText').textContent = 'Bağlı: ' + 
                    form.querySelector('[name="host"]').value + ' - ' + 
                    form.querySelector('[name="dbname"]').value;
                loadTables();
            } else {
                alert('Bağlantı hatası: ' + res.error);
            }
        } catch (e) {
            alert('Bağlantı hatası');
        }
    });
}

function dbDisconnect() {
    document.getElementById('dbConnectForm').style.display = 'block';
    document.getElementById('dbConnected').style.display = 'none';
    document.getElementById('dbTables').innerHTML = '';
    document.getElementById('dbResults').innerHTML = '';
}

function loadTables() {
    ajax('?action=db_tables', 'GET', null, function(status, resp) {
        try {
            var res = JSON.parse(resp);
            if (res.ok) {
                var html = '';
                res.tables.forEach(function(table) {
                    html += '<div class="db-table-item" onclick="showTableStructure(\'' + escapeHtml(table) + '\')">' + 
                           escapeHtml(table) + '</div>';
                });
                document.getElementById('dbTables').innerHTML = html;
            } else {
                document.getElementById('dbTables').innerHTML = 'Hata: ' + escapeHtml(res.error);
            }
        } catch (e) {
            document.getElementById('dbTables').innerHTML = 'Yükleme hatası';
        }
    });
}

function showTableStructure(tableName) {
    ajax('?action=db_structure&table=' + encodeURIComponent(tableName), 'GET', null, function(status, resp) {
        try {
            var res = JSON.parse(resp);
            var resultsDiv = document.getElementById('dbResults');
            if (res.ok) {
                resultsDiv.innerHTML = '<h5>Tablo Yapısı: ' + escapeHtml(tableName) + '</h5>' +
                    '<pre style="background:rgba(0,0,0,0.3);padding:10px;border-radius:5px;overflow:auto;">' + 
                    escapeHtml(res.structure) + '</pre>';
            } else {
                resultsDiv.innerHTML = 'Hata: ' + escapeHtml(res.error);
            }
        } catch (e) {
            document.getElementById('dbResults').innerHTML = 'Yapı hatası';
        }
    });
}

function dbRunQuery() {
    var query = document.getElementById('dbQuery').value.trim();
    if (!query) return;
    
    var formData = new FormData();
    formData.append('csrf', '<?php echo csrf_token(); ?>');
    formData.append('query', query);
    
    ajax('?action=db_query', 'POST', formData, function(status, resp) {
        try {
            var res = JSON.parse(resp);
            var resultsDiv = document.getElementById('dbResults');
            
            if (res.ok) {
                var html = '<h5>Sorgu Sonuçları (' + res.time + 'ms)</h5>';
                
                if (res.data && res.data.length > 0) {
                    html += '<div style="max-height:300px;overflow:auto;">';
                    html += '<table style="width:100%;border-collapse:collapse;font-size:12px;">';
                    
                    // Başlıklar
                    html += '<tr style="background:rgba(255,255,255,0.05);">';
                    Object.keys(res.data[0]).forEach(function(key) {
                        html += '<th style="padding:6px;border:1px solid rgba(255,255,255,0.1);">' + 
                               escapeHtml(key) + '</th>';
                    });
                    html += '</tr>';
                    
                    // Veriler
                    res.data.forEach(function(row) {
                        html += '<tr>';
                        Object.values(row).forEach(function(value) {
                            html += '<td style="padding:6px;border:1px solid rgba(255,255,255,0.1);">' + 
                                   escapeHtml(value) + '</td>';
                        });
                        html += '</tr>';
                    });
                    
                    html += '</table>';
                    html += '</div>';
                    html += '<div style="margin-top:10px;color:var(--muted)">' + 
                           res.data.length + ' kayıt bulundu</div>';
                } else {
                    html += '<div style="color:var(--muted)">Etkilenen kayıt: ' + res.affected + '</div>';
                }
                
                resultsDiv.innerHTML = html;
            } else {
                resultsDiv.innerHTML = '<div style="color:var(--danger)">Hata: ' + escapeHtml(res.error) + '</div>';
            }
        } catch (e) {
            document.getElementById('dbResults').innerHTML = '<div style="color:var(--danger)">Sorgu hatası</div>';
        }
    });
}

/* ---------- TOPLU İŞLEMLER ---------- */
var selectedFiles = [];

// Dosya seçimi için checkbox'ları ekleyin
document.addEventListener('DOMContentLoaded', function() {
    // Her dosya kartına checkbox ekle
    document.querySelectorAll('.file-card').forEach(function(card) {
        var path = card.getAttribute('data-path');
        if (!path) return;
        
        var checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'file-checkbox';
        checkbox.value = path;
        checkbox.style.marginRight = '10px';
        checkbox.addEventListener('change', function() {
            updateSelectedFiles();
        });
        
        var fileRow = card.querySelector('.file-row');
        if (fileRow) {
            fileRow.insertBefore(checkbox, fileRow.firstChild);
        }
    });
});

function updateSelectedFiles() {
    selectedFiles = [];
    document.querySelectorAll('.file-checkbox:checked').forEach(function(cb) {
        selectedFiles.push(cb.value);
    });
    
    var listDiv = document.getElementById('selectedFilesList');
    var html = '';
    
    if (selectedFiles.length > 0) {
        html += '<ul>';
        selectedFiles.forEach(function(file) {
            html += '<li>' + escapeHtml(file) + '</li>';
        });
        html += '</ul>';
        html += '<div style="color:var(--muted);margin-top:10px;">' + 
               selectedFiles.length + ' dosya seçildi</div>';
    } else {
        html = '<div style="color:var(--muted)">Henüz dosya seçilmedi</div>';
    }
    
    listDiv.innerHTML = html;
    
    // Hedef alanını göster/gizle
    var opSelect = document.getElementById('batchOperation');
    var targetContainer = document.getElementById('batchTargetContainer');
    if (['move', 'copy', 'zip_selected'].includes(opSelect.value)) {
        targetContainer.style.display = 'block';
    } else {
        targetContainer.style.display = 'none';
    }
}

// İşlem seçimi değiştiğinde
document.getElementById('batchOperation').addEventListener('change', updateSelectedFiles);

function runBatchOperation() {
    if (selectedFiles.length === 0) {
        alert('Lütfen en az bir dosya seçin');
        return;
    }
    
    var operation = document.getElementById('batchOperation').value;
    var target = document.getElementById('batchTarget').value;
    
    var confirmMsg = {
        'delete': 'Seçili ' + selectedFiles.length + ' dosyayı silmek istediğinize emin misiniz?',
        'chmod_644': 'Seçili ' + selectedFiles.length + ' dosyanın izinlerini 644 yapmak istiyor musunuz?',
        'chmod_755': 'Seçili ' + selectedFiles.length + ' dosyanın izinlerini 755 yapmak istiyor musunuz?',
        'move': 'Seçili dosyaları taşımak istediğinize emin misiniz?',
        'copy': 'Seçili dosyaları kopyalamak istediğinize emin misiniz?',
        'zip_selected': 'Seçili dosyaları ZIP yapmak istiyor musunuz?'
    }[operation];
    
    if (!confirm(confirmMsg || 'İşlemi gerçekleştirmek istediğinize emin misiniz?')) {
        return;
    }
    
    var formData = new FormData();
    formData.append('csrf', '<?php echo csrf_token(); ?>');
    formData.append('operation', operation);
    formData.append('files', JSON.stringify(selectedFiles));
    if (target) formData.append('target', target);
    
    var resultsDiv = document.getElementById('batchResults');
    resultsDiv.innerHTML = '<div style="color:var(--muted)">İşlem çalıştırılıyor...</div>';
    
    ajax('?action=batch_operations', 'POST', formData, function(status, resp) {
        try {
            var res = JSON.parse(resp);
            if (res.ok) {
                var html = '<h4>İşlem Sonuçları</h4>';
                var successCount = 0;
                var errorCount = 0;
                
                html += '<table style="width:100%;border-collapse:collapse;font-size:12px;">';
                html += '<tr><th>Dosya</th><th>Durum</th><th>Mesaj</th></tr>';
                
                for (var file in res.results) {
                    var result = res.results[file];
                    if (result.success) {
                        successCount++;
                        html += '<tr style="background:rgba(52,211,153,0.1)">';
                    } else {
                        errorCount++;
                        html += '<tr style="background:rgba(255,107,107,0.1)">';
                    }
                    
                    html += '<td style="padding:6px">' + escapeHtml(file) + '</td>';
                    html += '<td style="padding:6px">' + (result.success ? '✅' : '❌') + '</td>';
                    html += '<td style="padding:6px">' + escapeHtml(result.error || 'Başarılı') + '</td>';
                    html += '</tr>';
                }
                
                html += '</table>';
                html += '<div style="margin-top:10px;color:var(--muted)">' + 
                       'Sonuç: ' + successCount + ' başarılı, ' + errorCount + ' hatalı</div>';
                
                resultsDiv.innerHTML = html;
                
                // Sayfayı yenile (dosya listesini güncelle)
                if (successCount > 0 && ['delete', 'move'].includes(operation)) {
                    setTimeout(function() {
                        window.location.reload();
                    }, 2000);
                }
            } else {
                resultsDiv.innerHTML = '<div style="color:var(--danger)">Hata: ' + escapeHtml(res.error) + '</div>';
            }
        } catch (e) {
            resultsDiv.innerHTML = '<div style="color:var(--danger)">Beklenmeyen yanıt</div>';
        }
    });
}

function clearSelection() {
    document.querySelectorAll('.file-checkbox').forEach(function(cb) {
        cb.checked = false;
    });
    selectedFiles = [];
    updateSelectedFiles();
}

/* ---------- YARDIMCI FONKSİYONLAR ---------- */
function escapeHtml(text) {
    var map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}
</script>

</body>
</html>
