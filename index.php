<?php
/**
 * NotesApp - Simple Note Manager
 * WARNING: This application is INTENTIONALLY VULNERABLE.
 * DO NOT deploy in production. For educational purposes only.
 */

// ===== SECURITY ISSUE: Error reporting enabled in production =====
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// ===== SECURITY ISSUE: Hardcoded credentials =====
define('ADMIN_USER', 'admin');
define('ADMIN_PASS', '21232f297a57a5a743894a0e4a801fc3'); // MD5 hash of "admin"
define('DB_PATH', __DIR__ . '/data/notes.db');
define('UPLOAD_DIR', __DIR__ . '/uploads/');
define('SECRET_KEY', 'SuperSecretKey123!');

// ===== SECURITY ISSUE: Weak session management, no HttpOnly, no Secure flag =====
session_start();

// Initialize directories
if (!is_dir(__DIR__ . '/data')) {
    mkdir(__DIR__ . '/data', 0777, true);
}
if (!is_dir(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0777, true);
}

// ===== SECURITY ISSUE: SQLite DB in web-accessible location =====
$db = new SQLite3(DB_PATH);
$db->enableExceptions(true);

// Create tables
$db->exec("CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)");

// Insert default admin if not exists
$check = $db->querySingle("SELECT COUNT(*) FROM users WHERE username='admin'");
if (!$check) {
    $db->exec("INSERT INTO users (username, password) VALUES ('admin', '" . ADMIN_PASS . "')");
}

// ===== "Authentication" - easily bypassable =====
$logged_in = isset($_SESSION['user']);

// ===== SECURITY ISSUE: Using extract() on untrusted input =====
extract($_REQUEST);

// ===== Router =====
$action = isset($_GET['action']) ? $_GET['action'] : 'list';

// ===== SECURITY ISSUE: No CSRF protection on any form =====
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NotesApp - Simple Note Manager</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
        .note { background: #fff; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .note h3 { margin: 0 0 5px 0; }
        textarea, input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
        .btn { padding: 8px 15px; border: none; border-radius: 3px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background: #007bff; color: #fff; }
        .btn-danger { background: #dc3545; color: #fff; }
        .btn-success { background: #28a745; color: #fff; }
        .btn-warning { background: #ffc107; color: #000; }
        nav { background: #333; padding: 10px; margin-bottom: 20px; border-radius: 5px; }
        nav a { color: #fff; margin-right: 15px; text-decoration: none; }
        .alert { padding: 10px; margin: 10px 0; border-radius: 3px; }
        .alert-info { background: #d1ecf1; border: 1px solid #bee5eb; }
        .message { background: #fff; border-left: 4px solid #007bff; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>&#128221; NotesApp</h1>
    <nav>
        <a href="?action=list">&#127968; Home</a>
        <a href="?action=create">&#10133; New Note</a>
        <a href="?action=upload_form">&#128206; Upload File</a>
        <?php if ($logged_in): ?>
            <a href="?action=logout">Logout (<?php echo $_SESSION['user']; ?>)</a>
        <?php else: ?>
            <a href="?action=login_form">&#128274; Login</a>
        <?php endif; ?>
    </nav>

    <?php
    // ===== SECURITY ISSUE: Reflected XSS via error messages with user input =====
    if (isset($_GET['msg'])) {
        echo '<div class="alert alert-info">' . $_GET['msg'] . '</div>';
    }
    ?>

    <?php
    switch ($action) {

        // ============================
        // LOGIN
        // ============================
        case 'login_form':
            ?>
            <h2>Login</h2>
            <form method="POST" action="?action=login">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
            <p><small>Hint: admin / admin</small></p>
            <?php
            break;

        case 'login':
            // ===== SECURITY ISSUE: Weak MD5 hashing, no rate limiting, SQL injection in username =====
            $username = $_POST['username'];
            $password = md5($_POST['password']); // MD5 - cryptographically broken

            $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
            $result = $db->query($query);

            if ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $_SESSION['user'] = $row['username'];
                // ===== SECURITY ISSUE: No session regeneration on login (session fixation) =====
                echo '<div class="alert alert-info">Welcome, ' . $row['username'] . '!</div>';
                echo '<p><a href="?action=list">Go to notes</a></p>';
            } else {
                // ===== SECURITY ISSUE: Verbose error message helps attacker enumerate users =====
                echo '<div class="alert alert-info">Login failed for user: ' . $_POST['username'] . '</div>';
                echo '<p><a href="?action=login_form">Try again</a></p>';
            }
            break;

        case 'logout':
            // ===== SECURITY ISSUE: No session destruction, just unsets one key =====
            unset($_SESSION['user']);
            echo '<div class="alert alert-info">Logged out.</div>';
            echo '<p><a href="?action=list">Go to notes</a></p>';
            break;

        // ============================
        // LIST NOTES
        // ============================
        case 'list':
            // ===== SECURITY ISSUE: Reflected XSS in search + SQL injection =====
            $search = isset($_GET['search']) ? $_GET['search'] : '';

            echo '<h2>Notes</h2>';
            echo '<form method="GET" action="">';
            echo '<input type="hidden" name="action" value="list">';
            // ===== SECURITY ISSUE: Reflected XSS - echoing search query directly =====
            echo '<input type="text" name="search" placeholder="Search notes..." value="' . $search . '">';
            echo '<button type="submit" class="btn btn-primary">Search</button>';
            echo '</form>';

            // ===== SECURITY ISSUE: SQL Injection - search term directly in query =====
            if ($search) {
                $sql = "SELECT * FROM notes WHERE title LIKE '%$search%' OR content LIKE '%$search%' ORDER BY id DESC";
            } else {
                $sql = "SELECT * FROM notes ORDER BY id DESC";
            }

            $result = $db->query($sql);

            echo '<hr>';
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                // ===== SECURITY ISSUE: Stored XSS - no htmlspecialchars on output =====
                echo '<div class="note">';
                echo '<h3>' . $row['title'] . '</h3>';
                echo '<p>' . substr($row['content'], 0, 200) . '...</p>';
                echo '<small>' . $row['created_at'] . '</small><br>';
                echo '<a href="?action=view&id=' . $row['id'] . '" class="btn btn-primary btn-sm">View</a> ';
                echo '<a href="?action=delete&id=' . $row['id'] . '" class="btn btn-danger btn-sm" onclick="return confirm(\'Delete?\')">Delete</a>';
                echo '</div>';
            }
            break;

        // ============================
        // CREATE NOTE
        // ============================
        case 'create':
            // ===== SECURITY ISSUE: No auth check for create =====
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $title = $_POST['title'];
                $content = $_POST['content'];

                // ===== SECURITY ISSUE: SQL Injection =====
                $sql = "INSERT INTO notes (title, content) VALUES ('$title', '$content')";
                $db->exec($sql);

                echo '<div class="alert alert-info">Note created successfully!</div>';
                echo '<p><a href="?action=list">Back to notes</a></p>';
            } else {
                ?>
                <h2>Create Note</h2>
                <form method="POST" action="?action=create">
                    <input type="text" name="title" placeholder="Note title" required><br>
                    <textarea name="content" rows="10" placeholder="Note content..." required></textarea><br>
                    <button type="submit" class="btn btn-success">Save Note</button>
                </form>
                <?php
            }
            break;

        // ============================
        // VIEW NOTE
        // ============================
        case 'view':
            // ===== SECURITY ISSUE: SQL Injection in ID parameter =====
            $id = $_GET['id'];
            $sql = "SELECT * FROM notes WHERE id = $id";
            $result = $db->query($sql);
            $note = $result->fetchArray(SQLITE3_ASSOC);

            if ($note) {
                // ===== SECURITY ISSUE: Stored XSS - no escaping on output =====
                echo '<h2>' . $note['title'] . '</h2>';
                echo '<small>Created: ' . $note['created_at'] . '</small>';
                echo '<div class="message">' . nl2br($note['content']) . '</div>';
                // ===== SECURITY ISSUE: IDOR - anyone can view/edit/delete any note =====
                echo '<a href="?action=delete&id=' . $note['id'] . '" class="btn btn-danger">Delete</a> ';
                echo '<a href="?action=list" class="btn btn-primary">Back</a>';
            } else {
                echo '<div class="alert alert-info">Note not found with ID: ' . $id . '</div>';
            }
            break;

        // ============================
        // DELETE NOTE
        // ============================
        case 'delete':
            // ===== SECURITY ISSUE: SQL Injection, no auth check, no CSRF, GET request mutates state =====
            $id = $_GET['id'];
            $sql = "DELETE FROM notes WHERE id = $id";
            $db->exec($sql);
            echo '<div class="alert alert-info">Note deleted!</div>';
            echo '<p><a href="?action=list">Back to notes</a></p>';
            break;

        // ============================
        // UPLOAD FILE - INSECURE
        // ============================
        case 'upload_form':
            ?>
            <h2>Upload File</h2>
            <form method="POST" action="?action=upload" enctype="multipart/form-data">
                <input type="file" name="file" required><br>
                <button type="submit" class="btn btn-primary">Upload</button>
            </form>
            <hr>
            <h3>Uploaded Files:</h3>
            <?php
            // List uploaded files
            $files = scandir(UPLOAD_DIR);
            foreach ($files as $f) {
                if ($f != '.' && $f != '..') {
                    echo '<div><a href="?action=view_file&file=' . $f . '">' . $f . '</a></div>';
                }
            }
            break;

        case 'upload':
            // ===== SECURITY ISSUE: No file type validation, no size limit, PHP files accepted =====
            $target = UPLOAD_DIR . $_FILES['file']['name'];

            if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
                // ===== SECURITY ISSUE: Path disclosure in success message =====
                echo '<div class="alert alert-info">File uploaded to: ' . $target . '</div>';
            } else {
                echo '<div class="alert alert-info">Upload failed!</div>';
            }
            echo '<p><a href="?action=upload_form">Back to uploads</a></p>';
            break;

        case 'view_file':
            // ===== SECURITY ISSUE: Path traversal vulnerability =====
            $file = $_GET['file'];
            $filepath = UPLOAD_DIR . $file;

            echo '<h2>File: ' . $file . '</h2>';

            if (file_exists($filepath)) {
                // ===== SECURITY ISSUE: No content-type validation, XSS possible, source code disclosure =====
                echo '<pre>' . htmlspecialchars(file_get_contents($filepath)) . '</pre>';
            } else {
                echo '<div class="alert alert-info">File not found</div>';
            }
            echo '<p><a href="?action=upload_form">Back to uploads</a></p>';
            break;

        // ============================
        // DEBUG / EVAL - RCE BACKDOOR
        // ============================
        case 'debug':
            // ===== SECURITY ISSUE: Intentional backdoor - eval() on user input =====
            if (isset($_POST['code'])) {
                echo '<h3>Result:</h3>';
                echo '<pre>';
                eval($_POST['code']);
                echo '</pre>';
            }
            ?>
            <h2>Debug Console</h2>
            <form method="POST" action="?action=debug">
                <textarea name="code" rows="5" placeholder="Enter PHP code..."></textarea><br>
                <button type="submit" class="btn btn-warning">Execute</button>
            </form>
            <?php
            break;

        // ============================
        // EXPORT NOTES
        // ============================
        case 'export':
            // ===== SECURITY ISSUE: Information disclosure - exports all data without auth =====
            header('Content-Type: application/json');
            $result = $db->query("SELECT * FROM notes");
            $notes = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $notes[] = $row;
            }
            echo json_encode($notes, JSON_PRETTY_PRINT);
            exit;

        // ============================
        // SQLITE INFO LEAK
        // ============================
        case 'info':
            // ===== SECURITY ISSUE: PHP info disclosure =====
            phpinfo();
            exit;

        default:
            echo '<div class="alert alert-info">Unknown action.</div>';
            echo '<p><a href="?action=list">Go to notes</a></p>';
    }
    ?>

    <hr>
    <footer style="color: #999; font-size: 12px;">
        NotesApp v1.0 | PHP <?php echo phpversion(); ?> | SQLite <?php echo SQLite3::version()['versionString']; ?>
        <!-- SECURITY ISSUE: Version disclosure in footer -->
    </footer>
</body>
</html>
