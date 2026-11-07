<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\Psr7\UriResolver;



/**
 * Output data as JSON and terminate the current request.
 *
 * @param mixed $data
 * @param int   $status
 * @return never
 */
function sendJsonResponse($data, $status = 200)
{
    http_response_code($status);
    echo json_encode($data);
    exit;
}


$method = $_SERVER['REQUEST_METHOD'];
$data = $_GET;

const ENABLE_CORS = true;

if (ENABLE_CORS) {
	header('Access-Control-Allow-Origin: *');
	header('Access-Control-Allow-Methods: GET, OPTIONS');
	header('Access-Control-Allow-Headers: Content-Type');
	header('Access-Control-Max-Age: 86400');
	header('Allow: GET, OPTIONS');
}

if (ENABLE_CORS && $method === 'OPTIONS') {
	http_response_code(204);
	exit;
}

if ($method !== 'GET') {
	header('Allow: ' . (ENABLE_CORS ? 'GET, OPTIONS' : 'GET'));
	http_response_code(405);
	sendJsonResponse(array('error' => 'Method Not Allowed'), 405);
}

if (empty($data['url'])) {
	sendJsonResponse([
		'status' => 'failed',
		'message' => 'Please provide a url.',
	], 400);
}

$LOCAL_IPV6_PREFIXES = getLocalIpv6Prefixes();



const MAX_REDIRECTS = 5;
const CONNECT_TIMEOUT = 5;
const TOTAL_TIMEOUT = 15;
const ALLOWED_PORTS = [80, 443];










/*
 * Fetch a URL while manually following redirects.
 *
 * $allowedPorts:
 *
 *   [80, 443]        only allow ports 80 and 443
 *   [80, 443, 8080]  only allow ports 80, 443 and 8080
 *   null             only allow default ports defined in ALLOWED_PORTS
 */
function fetchUrlSafely(
	string $url,
	?array $allowedPorts = null
): array {
	$allowedPorts = $allowedPorts ?? ALLOWED_PORTS;
	$currentUrl = $url;

	for ($redirects = 0; $redirects <= MAX_REDIRECTS; $redirects++) {
		$response = fetchOneHop(
			$currentUrl,
			$allowedPorts
		);

		$status = $response['status'];

		/*
         * Not a redirect.
         */
		if ($status < 300 || $status >= 400) {
			$response['final_url'] = $currentUrl;
			$response['redirects'] = $redirects;

			return $response;
		}

		/*
         * Get Location header.
         */
		$location = getLastHeader(
			$response['headers'],
			'location'
		);

		/*
         * 3xx without Location.
         */
		if ($location === null) {
			$response['final_url'] = $currentUrl;
			$response['redirects'] = $redirects;

			return $response;
		}

		/*
         * Resolve relative Location against current URL.
         */
		$currentUrl = resolveRedirectUrl(
			$currentUrl,
			$location
		);
	}

	throw new RuntimeException(
		'Too many redirects'
	);
}


/*
 * Perform exactly ONE HTTP request.
 *
 * cURL does NOT automatically follow redirects.
 */
function fetchOneHop(
	string $url,
	?array $allowedPorts
): array {
	$destination = validateDestination(
		$url,
		$allowedPorts
	);

	$host = $destination['host'];
	$port = $destination['port'];
	$ips = $destination['ips'];
	$hostIsIp = $destination['host_is_ip'];

	/*
     * Parsed headers.
     */
	$headers = [];

	/*
     * Exact raw header block returned by the server.
     */
	$rawHeaders = '';

	$curl = curl_init($url);

	if ($curl === false) {
		throw new RuntimeException(
			'Could not initialize cURL'
		);
	}

	$options = [
		/*
         * Return response body from curl_exec().
         */
		CURLOPT_RETURNTRANSFER => true,

		/*
         * We handle redirects ourselves.
         */
		CURLOPT_FOLLOWLOCATION => false,

		CURLOPT_CONNECTTIMEOUT => CONNECT_TIMEOUT,
		CURLOPT_TIMEOUT => TOTAL_TIMEOUT,

		/*
         * Only HTTP and HTTPS.
         */
		CURLOPT_PROTOCOLS =>
		CURLPROTO_HTTP | CURLPROTO_HTTPS,

		/*
         * Keep TLS verification enabled.
         */
		CURLOPT_SSL_VERIFYPEER => true,
		CURLOPT_SSL_VERIFYHOST => 2,

		/*
         * Collect response headers.
         */
		CURLOPT_HEADERFUNCTION =>
		function (
			$curl,
			string $line
		) use (
			&$headers,
			&$rawHeaders
		): int {
			$length = strlen($line);

			/*
                 * A new HTTP response block can occur, for example
                 * after an HTTP 100 response.
                 *
                 * We only want the final response block.
                 */
			if (str_starts_with($line, 'HTTP/')) {
				$headers = [];
				$rawHeaders = '';
			}

			/*
                 * Preserve the exact raw header data.
                 */
			$rawHeaders .= $line;

			/*
                 * Now also parse the header.
                 */
			$trimmedLine = trim($line);

			if ($trimmedLine === '') {
				return $length;
			}

			/*
                 * Status line, not a normal header.
                 */
			if (str_starts_with($trimmedLine, 'HTTP/')) {
				return $length;
			}

			$pos = strpos(
				$trimmedLine,
				':'
			);

			if ($pos === false) {
				return $length;
			}

			$name = strtolower(
				trim(
					substr(
						$trimmedLine,
						0,
						$pos
					)
				)
			);

			$value = trim(
				substr(
					$trimmedLine,
					$pos + 1
				)
			);

			/*
                 * Keep multiple headers with the same name.
                 *
                 * For example multiple Set-Cookie headers.
                 */
			$headers[$name][] = $value;

			return $length;
		},
	];


	/*
     * If this is a hostname rather than a literal IP,
     * pin cURL to the addresses we already checked.
     */
	if (!$hostIsIp) {
		$curlIps = [];

		foreach ($ips as $ip) {
			if (str_contains($ip, ':')) {
				/*
                 * IPv6.
                 */
				$curlIps[] = '[' . $ip . ']';
			} else {
				/*
                 * IPv4.
                 */
				$curlIps[] = $ip;
			}
		}

		$resolveEntry =
			$host
			. ':'
			. $port
			. ':'
			. implode(',', $curlIps);

		$options[CURLOPT_RESOLVE] = [
			$resolveEntry
		];
	}


	curl_setopt_array(
		$curl,
		$options
	);

	/*
     * Because CURLOPT_RETURNTRANSFER is true,
     * curl_exec() returns the BODY.
     *
     * Headers are collected separately by
     * CURLOPT_HEADERFUNCTION.
     */
	$body = curl_exec($curl);

	if ($body === false) {
		$error = curl_error($curl);
		throw new RuntimeException(
			'cURL error: ' . $error
		);
	}

	$status = curl_getinfo(
		$curl,
		CURLINFO_RESPONSE_CODE
	);

	$connectedIp = curl_getinfo(
		$curl,
		CURLINFO_PRIMARY_IP
	);



	/*
     * Defense in depth.
     *
     * Verify cURL actually connected to one of
     * the IP addresses we approved.
     */
	if (!ipIsApproved($connectedIp, $ips)) {
		throw new RuntimeException(
			'cURL connected to an unexpected IP: '
				. $connectedIp
		);
	}


	/*
     * Return both headers and body.
     */
	return [
		'status' => $status,

		/*
         * Parsed headers:
         *
         * [
         *     'content-type' => ['text/html'],
         *     'server' => ['nginx'],
         *     ...
         * ]
         */
		'headers' => $headers,

		/*
         * Original HTTP response headers as a string.
         */
		'raw_headers' => $rawHeaders,

		/*
         * Response body.
         */
		'body' => $body,

		/*
         * Actual remote IP.
         */
		'connected_ip' => $connectedIp,
	];
}


/*
 * Parse and validate one destination URL.
 */
function validateDestination(
	string $url,
	?array $allowedPorts
): array {
	$uri = new Uri($url);

	$scheme = strtolower(
		$uri->getScheme()
	);

	/*
     * Only HTTP and HTTPS.
     */
	if (
		$scheme !== 'http' &&
		$scheme !== 'https'
	) {
		throw new RuntimeException(
			'Only http and https URLs are allowed'
		);
	}

	/*
     * Reject:
     *
     * http://user:password@example.com/
     */
	if ($uri->getUserInfo() !== '') {
		throw new RuntimeException(
			'User/password information in URLs is not allowed'
		);
	}

	$host = $uri->getHost();

	if ($host === '') {
		throw new RuntimeException(
			'URL has no hostname'
		);
	}

	/*
     * Is the host already an IPv4 or IPv6 address?
     */
	$hostIsIp =
		filter_var(
			$host,
			FILTER_VALIDATE_IP
		) !== false;

	/*
     * Determine effective port.
     */
	$port = $uri->getPort();

	if ($port === null) {
		if ($scheme === 'https') {
			$port = 443;
		} else {
			$port = 80;
		}
	}

	/*
     * Optional port filtering.
     *
     * null = allow any port.
     */
	if (
		$allowedPorts !== null &&
		!in_array(
			$port,
			$allowedPorts,
			true
		)
	) {
		throw new RuntimeException(
			'Port not allowed: ' . $port
		);
	}

	/*
     * Resolve hostname or validate literal IP.
     */
	$ips = resolveAndValidateHost(
		$host
	);

	return [
		'host' => $host,
		'port' => $port,
		'ips' => $ips,
		'host_is_ip' => $hostIsIp,
	];
}


/*
 * Read the current machine's global IPv6 addresses and
 * collapse them to /64 prefixes.
 *
 * This is intentionally done once at the start of a request,
 * so redirect resolution can compare against the local IPv6
 * network without repeated system calls.
 */
function getLocalIpv6Prefixes(): array {
	$output = [];
	$lines = [];

	@exec(
		'ip -6 -o addr show scope global 2>/dev/null',
		$lines,
		$status
	);

	if ($status !== 0 || $lines === []) {
		return [];
	}

	foreach ($lines as $line) {
		if (!preg_match('/\sinet6\s+([0-9A-Fa-f:]+)\/(\d+)/', $line, $matches)) {
			continue;
		}

		$address = $matches[1];
		$prefixLength = (int) $matches[2];

		if ($prefixLength !== 64) {
			continue;
		}

		$prefix = ipv6PrefixTo64($address);

		if ($prefix !== '') {
			$output[] = $prefix;
		}
	}

	return array_values(array_unique($output));
}

function ipv6PrefixTo64(string $address): string {
	$packed = @inet_pton($address);

	if ($packed === false || strlen($packed) !== 16) {
		return '';
	}

	$prefix = substr($packed, 0, 8) . str_repeat("\0", 8);

	return inet_ntop($prefix);
}

function ipMatchesLocalIpv6Prefix(
	string $ip,
	array $localPrefixes
): bool {
	$packed = @inet_pton($ip);

	if ($packed === false || strlen($packed) !== 16) {
		return false;
	}

	$ipPrefix = substr($packed, 0, 8);

	foreach ($localPrefixes as $prefix) {
		$prefixPacked = @inet_pton($prefix);

		if ($prefixPacked === false || strlen($prefixPacked) !== 16) {
			continue;
		}

		if (substr($prefixPacked, 0, 8) === $ipPrefix) {
			return true;
		}
	}

	return false;
}

/*
 * Resolve and validate a host.
 *
 * Handles:
 *
 * example.com
 * 8.8.8.8
 * 2606:4700:4700::1111
 */
function resolveAndValidateHost(
	string $host
): array {
	/*
     * Literal IPv4 or IPv6.
     */
	if (
		filter_var(
			$host,
			FILTER_VALIDATE_IP
		) !== false
	) {
		assertPublicIp($host);

		return [$host];
	}

	/*
     * Resolve:
     *
     * A     = IPv4
     * AAAA  = IPv6
     */
	$records = dns_get_record(
		$host,
		DNS_A | DNS_AAAA
	);

	if ($records === false) {
		throw new RuntimeException(
			'DNS resolution failed for: '
				. $host
		);
	}

	$ips = [];

	foreach ($records as $record) {
		if (isset($record['ip'])) {
			$ips[] = $record['ip'];
		}

		if (isset($record['ipv6'])) {
			$ips[] = $record['ipv6'];
		}
	}

	/*
     * Remove duplicate IPs.
     */
	$ips = array_values(
		array_unique($ips)
	);

	if (!$ips) {
		throw new RuntimeException(
			'Hostname has no A or AAAA records: '
				. $host
		);
	}

	/*
     * Reject the entire hostname if ANY resolved
     * address is private, reserved, or local to this machine.
     */
	foreach ($ips as $ip) {
		assertPublicIp($ip);
	}

	return $ips;
}


/*
 * Reject private/reserved IPv4 and IPv6 addresses.
 * Also reject IPv6 addresses that share the machine's
 * local /64 prefix, which could point to local devices.
 */
function assertPublicIp(
	string $ip
): void {
	$result = filter_var(
		$ip,
		FILTER_VALIDATE_IP,
		FILTER_FLAG_NO_PRIV_RANGE |
			FILTER_FLAG_NO_RES_RANGE
	);

	if ($result === false) {
		throw new RuntimeException(
			'Private or reserved IP rejected: '
				. $ip
		);
	}

	if (
		strpos($ip, ':') !== false &&
		ipMatchesLocalIpv6Prefix(
			$ip,
			$GLOBALS['LOCAL_IPV6_PREFIXES'] ?? []
		)
	) {
		throw new RuntimeException(
			'IPv6 address matches a local machine /64 prefix: '
				. $ip
		);
	}
}


/*
 * Resolve Location against the URL that produced
 * the redirect.
 *
 * Example:
 *
 * Current:
 * https://example.com/a/b/page.html
 *
 * Location:
 * ../login
 *
 * Result:
 * https://example.com/a/login
 */
function resolveRedirectUrl(
	string $currentUrl,
	string $location
): string {
	$location = trim($location);

	if ($location === '') {
		throw new RuntimeException(
			'Empty redirect Location'
		);
	}

	return (string) UriResolver::resolve(
		new Uri($currentUrl),
		new Uri($location)
	);
}


/*
 * Return the last occurrence of a response header.
 */
function getLastHeader(
	array $headers,
	string $name
): ?string {
	$name = strtolower($name);

	if (empty($headers[$name])) {
		return null;
	}

	return end(
		$headers[$name]
	);
}


/*
 * Verify the actual IP used by cURL is one of
 * the IPs we previously approved.
 */
function ipIsApproved(
	string $actualIp,
	array $approvedIps
): bool {
	$actualPacked = @inet_pton(
		$actualIp
	);

	if ($actualPacked === false) {
		return false;
	}

	foreach ($approvedIps as $approvedIp) {
		$approvedPacked = @inet_pton(
			$approvedIp
		);

		if (
			$approvedPacked !== false &&
			$actualPacked === $approvedPacked
		) {
			return true;
		}
	}

	return false;
}


try {
	$result = fetchUrlSafely(
		$data['url']
	);

	$contentType = getLastHeader(
		$result['headers'],
		'content-type'
	);

	if ($contentType === null || $contentType === '') {
		$contentType = 'application/octet-stream';
	}

	header('Content-Type: ' . $contentType);
	header('Content-Length: ' . strlen($result['body']));
	echo $result['body'];
	exit;
} catch (Throwable $e) {
	sendJsonResponse([
		'status' => 'failed',
		'message' => $e->getMessage(),
	], 500);
}
