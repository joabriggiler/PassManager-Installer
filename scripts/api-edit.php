<?php
error_reporting(0); // Desactiva la impresión de Warnings en la respuesta

// 1. CONFIGURACIÓN CORS (Debe ir al principio de todo)
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowed_origins = [
  'null', // Electron / file:// suele enviar Origin: null
  // si en algún momento corrés la UI en http://localhost:xxxx agregalo acá
  // 'http://localhost:3000',
];

if (in_array($origin, $allowed_origins, true)) {
  header("Access-Control-Allow-Origin: $origin");
}
header("Vary: Origin");
header("Access-Control-Allow-Credentials: false");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-Auth-Token");

// Responder inmediatamente a la petición de prueba OPTIONS
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

header("Content-Type: application/json; charset=UTF-8");

define('SECRET_KEY', getenv('APP_SECRET_KEY')); 
define('SECRET_IV', getenv('APP_SECRET_IV'));
define('METHOD', 'AES-256-CBC');

function encriptar_v1_cbc($data) {
    $key = hash('sha256', SECRET_KEY);
    $iv  = substr(hash('sha256', SECRET_IV), 0, 16);
    $output = openssl_encrypt($data, METHOD, $key, 0, $iv);
    return base64_encode($output);
}

function desencriptar_v1_cbc($data) {
    $key = hash('sha256', SECRET_KEY);
    $iv  = substr(hash('sha256', SECRET_IV), 0, 16);
    $output = openssl_decrypt(base64_decode($data), METHOD, $key, 0, $iv);
    return $output;
}

function encriptar($texto, $aad = '') {
    return encrypt_v2_gcm((string)$texto, $aad); // todo lo nuevo va v2
}

function desencriptar($texto, $aad = '') {
    $v2 = decrypt_v2_gcm($texto, $aad);
    if ($v2 !== null) return $v2;

    // fallback a lo viejo (v1 CBC)
    return desencriptar_v1_cbc($texto);
}

define('ENC_KEY_B64', getenv('APP_ENC_KEY_B64')); // 32 bytes en base64

function enc_key_32() {
    $k = base64_decode(ENC_KEY_B64, true);
    if ($k === false || strlen($k) !== 32) {
        throw new Exception("APP_ENC_KEY_B64 inválida (debe ser base64 de 32 bytes).", 500);
    }
    return $k;
}

function encrypt_v2_gcm($plaintext, $aad = '') {
    $key = enc_key_32();
    $nonce = random_bytes(12); // recomendado para GCM
    $tag = '';
    $cipher = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $nonce,
        $tag,
        $aad,
        16
    );
    if ($cipher === false) throw new Exception("Error al encriptar (GCM).", 500);

    $blob = $nonce . $tag . $cipher; // 12 + 16 + n
    return 'v2:' . base64_encode($blob);
}

function decrypt_v2_gcm($stored, $aad = '') {
    if (strpos($stored, 'v2:') !== 0) return null;

    $key = enc_key_32();
    $blob = base64_decode(substr($stored, 3), true);
    if ($blob === false || strlen($blob) < 12 + 16 + 1) throw new Exception("Ciphertext inválido.", 500);

    $nonce = substr($blob, 0, 12);
    $tag   = substr($blob, 12, 16);
    $cipher= substr($blob, 28);

    $plain = openssl_decrypt(
        $cipher,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $nonce,
        $tag,
        $aad
    );
    if ($plain === false) throw new Exception("No se pudo desencriptar (AAD mismatch o datos corruptos).", 500);
    return $plain;
}

define('JWT_SECRET', getenv('APP_JWT_SECRET')); // NUEVO env var
if (!JWT_SECRET || strlen(JWT_SECRET) < 32) {
    throw new Exception("APP_JWT_SECRET faltante o demasiado corto.", 500);
}

define('JWT_ISS', 'passmanager-api');
define('ACCESS_TTL_SECONDS', 900); // 15 min
define('REFRESH_TTL_SECONDS', 60 * 60 * 24 * 30); // 30 días

function b64url_enc($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function b64url_dec($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) $data .= str_repeat('=', 4 - $remainder);
    return base64_decode(strtr($data, '-_', '+/'));
}

function jwt_sign(array $payload) {
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    $segments = [
        b64url_enc(json_encode($header)),
        b64url_enc(json_encode($payload)),
    ];
    $signing_input = implode('.', $segments);
    $sig = hash_hmac('sha256', $signing_input, JWT_SECRET, true);
    $segments[] = b64url_enc($sig);
    return implode('.', $segments);
}

function jwt_verify($jwt) {
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) return null;

    [$h64, $p64, $s64] = $parts;
    $sig = b64url_dec($s64);
    $valid = hash_hmac('sha256', "$h64.$p64", JWT_SECRET, true);

    if (!hash_equals($valid, $sig)) return null;

    $payload = json_decode(b64url_dec($p64), true);
    if (!is_array($payload)) return null;

    if (($payload['iss'] ?? '') !== JWT_ISS) return null;

    $now = time();
    if (($payload['exp'] ?? 0) < $now) return null;

    return $payload;
}

function issue_access_token($user_id) {
    $now = time();
    $payload = [
        'iss' => JWT_ISS,
        'iat' => $now,
        'exp' => $now + ACCESS_TTL_SECONDS,
        'sub' => (int)$user_id,
    ];
    return jwt_sign($payload);
}

function get_auth_header() {
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) return trim($_SERVER['HTTP_AUTHORIZATION']);
    if (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) return trim($_SERVER['REDIRECT_HTTP_AUTHORIZATION']);

    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        foreach ($headers as $k => $v) {
        if (strtolower($k) === 'authorization') return trim($v);
        if (strtolower($k) === 'x-auth-token') return 'Bearer ' . trim($v);
        }
    }

    if (!empty($_SERVER['HTTP_X_AUTH_TOKEN'])) return 'Bearer ' . trim($_SERVER['HTTP_X_AUTH_TOKEN']);

    return '';
}

function require_auth() {
    $auth = get_auth_header();

    if (!preg_match('/^Bearer\s+(.+)$/i', $auth, $m)) {
        throw new Exception("No autorizado (token faltante).", 401);
    }

    $payload = jwt_verify(trim($m[1]));
    if (!$payload) {
        throw new Exception("No autorizado (token inválido o expirado).", 401);
    }
    return (int)$payload['sub'];
}

function set_refresh_cookie($token) {
    // SameSite=None suele ser necesario en apps cross-origin (Electron -> API)
    setcookie('pm_refresh', $token, [
        'expires' => time() + REFRESH_TTL_SECONDS,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'None',
    ]);
}

function clear_refresh_cookie() {
    setcookie('pm_refresh', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'None',
    ]);
}

if (isset($data['email']) && strlen($data['email']) > 254) throw new Exception("Email inválido.", 400);
if (isset($data['auth_verifier']) && strlen($data['auth_verifier']) > 200) throw new Exception("Verificador inválido.", 400);
if (isset($data['refresh_token']) && strlen($data['refresh_token']) > 200) throw new Exception("Refresh inválido.", 400);

// URI de Supabase (Asegúrate de poner tu password real)
$db_uri = getenv('DATABASE_URL');

try {
    $conn = pg_connect($db_uri);
    if (!$conn) {
        throw new Exception("Error crítico: No se pudo conectar a la base de datos.");
    }

    $data = json_decode(file_get_contents("php://input"), true);
    $accion = $_GET['accion'] ?? '';

    switch ($accion) {
        
        // 1. REGISTRO CON DETECCIÓN DE DUPLICADOS
        case 'registro':
            if (
                empty($data['email']) ||
                empty($data['kdf_salt_b64']) ||
                empty($data['kdf_iter']) ||
                empty($data['auth_verifier'])
            ) {
                throw new Exception("Faltan datos para registro.", 400);
            }

            $email = trim($data['email']);
            $salt_b64 = $data['kdf_salt_b64'];
            $kdf_iter = (int)$data['kdf_iter'];
            $auth_verifier = $data['auth_verifier'];

            // Validaciones mínimas
            $salt_bytes = base64_decode($salt_b64, true);
            if ($salt_bytes === false || strlen($salt_bytes) < 16 || strlen($salt_bytes) > 64) {
                throw new Exception("Salt inválido.", 400);
            }
            if ($kdf_iter < 100000 || $kdf_iter > 2000000) {
                throw new Exception("Iteraciones inválidas.", 400);
            }

            // Guardar verifier con hash fuerte (servidor NO conoce la llave)
            $auth_verifier_hash = password_hash($auth_verifier, PASSWORD_ARGON2ID);

            $sql = "INSERT INTO usuarios (email, kdf_salt_b64, kdf_iter, auth_verifier_hash, zk_migrated_at)
                    VALUES ($1, $2, $3, $4, now())";
            $res = @pg_query_params($conn, $sql, [$email, $salt_b64, $kdf_iter, $auth_verifier_hash]);

            if (!$res) {
                $error_db = pg_last_error($conn);
                if (strpos($error_db, 'duplicate key') !== false) {
                    throw new Exception("Correo electrónico ya registrado.", 101);
                }
                throw new Exception("Error interno al registrar usuario.");
            }

            echo json_encode(["status" => "success", "message" => "Usuario registrado correctamente."]);
            break;


        // 2. LOGIN CON ERRORES ESPECÍFICOS

        case 'prelogin':
            if (empty($data['email'])) throw new Exception("Falta email.", 400);
            $email = trim($data['email']);

            $sql = "SELECT kdf_salt_b64, kdf_iter FROM usuarios WHERE email = $1";
            $res = pg_query_params($conn, $sql, [$email]);
            $row = pg_fetch_assoc($res);

            if (!$row) throw new Exception("Correo electrónico no registrado.", 102);

            echo json_encode([
                "status" => "success",
                "kdf_salt_b64" => $row["kdf_salt_b64"],
                "kdf_iter" => (int)$row["kdf_iter"],
            ]);
            break;

        case 'login':
            if (empty($data['email']) || empty($data['auth_verifier'])) {
                throw new Exception("Faltan datos: email y verificador.", 400);
            }

            $email = trim($data['email']);
            $auth_verifier = $data['auth_verifier'];

            $sql = "SELECT id, auth_verifier_hash FROM usuarios WHERE email = $1";
            $res = pg_query_params($conn, $sql, [$email]);
            $user = pg_fetch_assoc($res);

            if (!$user) throw new Exception("Correo electrónico no registrado.", 102);

            if (!password_verify($auth_verifier, $user['auth_verifier_hash'])) {
                usleep(250000); // 250ms
                throw new Exception("La contraseña es incorrecta.", 103);
            }

            $access = issue_access_token((int)$user['id']);

            // refresh token en DB (SIN cookie)
            $refresh = b64url_enc(random_bytes(48));
            $refresh_hash = hash('sha256', $refresh);
            $expires_at = gmdate('Y-m-d H:i:s', time() + REFRESH_TTL_SECONDS);

            $sql = "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)";
            $ok = pg_query_params($conn, $sql, [(int)$user['id'], $refresh_hash, $expires_at]);
            if (!$ok) throw new Exception("Error interno al crear sesión.", 500);

            echo json_encode([
                "status" => "success",
                "message" => "Login exitoso",
                "access_token" => $access,
                "refresh_token" => $refresh
            ]);
            break;


        case 'refresh':
            if (empty($data['refresh_token'])) throw new Exception("No autorizado (refresh faltante).", 401);

            $refresh = $data['refresh_token'];
            $hash = hash('sha256', $refresh);

            $sql = "SELECT user_id FROM refresh_tokens
                    WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
                    LIMIT 1";
            $res = pg_query_params($conn, $sql, [$hash]);
            $row = pg_fetch_assoc($res);

            if (!$row) throw new Exception("No autorizado (refresh inválido).", 401);

            // rotación
            $new_refresh = b64url_enc(random_bytes(48));
            $new_hash = hash('sha256', $new_refresh);
            $new_expires = gmdate('Y-m-d H:i:s', time() + REFRESH_TTL_SECONDS);

            pg_query_params($conn, "UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1", [$hash]);
            pg_query_params(
                $conn,
                "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
                [(int)$row['user_id'], $new_hash, $new_expires]
            );

            $access = issue_access_token((int)$row['user_id']);

            echo json_encode([
                "status" => "success",
                "access_token" => $access,
                "refresh_token" => $new_refresh
            ]);
            break;


        case 'logout':
            $auth_user_id = require_auth();
            pg_query_params($conn, "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [$auth_user_id]);
            echo json_encode(["status" => "success", "message" => "Sesión cerrada."]);
            break;

        // 3. GUARDAR SERVICIO
        case 'guardar_servicio':
            $auth_user_id = require_auth();
            if (empty($data['blob'])) throw new Exception("Falta blob cifrado.", 400);

            $blob = $data['blob'];
            if (!is_string($blob) || strlen($blob) > 50000) throw new Exception("Blob inválido.", 400);

            $sql = "INSERT INTO cuentas (usuario_id, blob) VALUES ($1, $2)";
            $res = pg_query_params($conn, $sql, [$auth_user_id, $blob]);

            if (!$res) throw new Exception("Error al guardar.", 500);
            echo json_encode(["status" => "success", "message" => "Servicio guardado correctamente."]);
            break;

        // 4. OBTENER CUENTAS DEL USUARIO
        case 'obtener_cuentas':
            $auth_user_id = require_auth();
            $sql = "SELECT id, blob FROM cuentas WHERE usuario_id = $1 ORDER BY id DESC";
            $res = pg_query_params($conn, $sql, [$auth_user_id]);
            if (!$res) throw new Exception("Error al obtener las cuentas.", 500);

            echo json_encode(["status" => "success", "cuentas" => (pg_fetch_all($res) ?: [])]);
            break;

        // 5. OBTENER UNA CUENTA ESPECÍFICA (Para edición)
        case 'obtener_una':
            $auth_user_id = require_auth();
            if (empty($data['id'])) throw new Exception("Falta id.", 400);

            $sql = "SELECT id, blob FROM cuentas WHERE id = $1 AND usuario_id = $2 LIMIT 1";
            $res = pg_query_params($conn, $sql, [(int)$data['id'], $auth_user_id]);
            $cuenta = pg_fetch_assoc($res);

            if (!$cuenta) throw new Exception("Cuenta no encontrada.", 404);

            echo json_encode(["status" => "success", "cuenta" => $cuenta]);
            break;

        case 'editar_servicio':
            $auth_user_id = require_auth();
            if (empty($data['id']) || empty($data['blob'])) throw new Exception("Faltan datos.", 400);

            $sql = "UPDATE cuentas SET blob = $1 WHERE id = $2 AND usuario_id = $3";
            $res = pg_query_params($conn, $sql, [$data['blob'], (int)$data['id'], $auth_user_id]);
            if (!$res) throw new Exception("Error al actualizar.", 500);

            echo json_encode(["status" => "success", "message" => "Servicio actualizado."]);
            break;

        case 'eliminar_servicio':
            $auth_user_id = require_auth();
            if (empty($data['id'])) throw new Exception("ID de cuenta no proporcionado.");
        
            $sql = "DELETE FROM cuentas WHERE id = $1 AND usuario_id = $2";
            $res = pg_query_params($conn, $sql, array((int)$data['id'], $auth_user_id));
        
            if (!$res || pg_affected_rows($res) === 0) {
                throw new Exception("No se pudo eliminar la cuenta o no tienes permisos.");
            }
        
            echo json_encode(["status" => "success", "message" => "Cuenta eliminada correctamente."]);
            break;

        default:
            throw new Exception("Acción desconocida o no válida.");
    }

} catch (Exception $e) {
    // Mantenemos 200 OK para que tu frontend lea el JSON, pero podrías usar 400 si quisieras.
    $code = (int)$e->getCode();
    if ($code === 401) http_response_code(401);
    else if ($code >= 400 && $code <= 599) http_response_code($code);
    else http_response_code(200);

    echo json_encode([
        "status" => "error",
        "message" => $e->getMessage(),
        "code"    => $e->getCode()
    ]);
}
?>