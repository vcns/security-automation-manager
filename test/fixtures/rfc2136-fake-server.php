<?php
/**
 * A minimal, single-connection RFC 2136 (DNS UPDATE over TCP) test double.
 *
 * Launched as a genuinely separate OS process (via proc_open() from
 * ProviderRfc2136Test) because Provider_Rfc2136::exchange() makes fully
 * blocking stream_socket_client()/fwrite()/fread() calls with no
 * interception point -- PHP has no user-registerable "tcp" stream
 * transport (stream_wrapper_register() covers fopen()-style wrappers, not
 * the transports stream_socket_client() uses), so a same-process fake
 * cannot interleave accept()/respond() with the driver's blocking calls.
 * A real, separate, loopback-only TCP listener is the only way to give
 * this driver a genuine request/response cycle to react to.
 *
 * Usage: php rfc2136-fake-server.php <mode> [<base64-response>]
 *   mode "close"   -- accept the connection, read the request, then close
 *                     without writing anything back.
 *   mode "respond" -- accept the connection, read the request, then write
 *                     back base64_decode(<base64-response>), length-prefixed.
 *                     Any occurrence of the two-byte sentinel "\xAA\xBB" in
 *                     the decoded response is first replaced with the
 *                     actual 2-byte DNS message ID this server just read
 *                     from the request -- the driver picks that ID via
 *                     wp_rand() at call time, so the parent test cannot
 *                     know it in advance when it constructs the response
 *                     template and launches this process.
 *
 * Protocol with the parent test process, over this script's own stdout:
 *   line 1: the ephemeral TCP port this script bound to on 127.0.0.1.
 *   line 2: base64 of the raw request bytes captured (the message body,
 *           excluding its 2-byte length prefix), or an empty line if the
 *           client never sent a complete length-prefixed message.
 */

declare( strict_types=1 );

$mode         = $argv[1] ?? 'close';
$response_b64 = $argv[2] ?? '';

$errno  = 0;
$errstr = '';
$server = stream_socket_server( 'tcp://127.0.0.1:0', $errno, $errstr );
if ( false === $server ) {
	fwrite( STDERR, "bind failed: {$errstr}\n" );
	exit( 1 );
}

$name = stream_socket_get_name( $server, false );
$port = (int) substr( $name, (int) strrpos( $name, ':' ) + 1 );
echo $port . "\n";
flush();

$conn = stream_socket_accept( $server, 30 );
if ( false === $conn ) {
	echo "\n";
	fclose( $server );
	exit( 1 );
}

$length_raw = fread( $conn, 2 );
$captured   = '';
if ( 2 === strlen( $length_raw ) ) {
	$length = unpack( 'n', $length_raw )[1];
	while ( strlen( $captured ) < $length ) {
		$chunk = fread( $conn, $length - strlen( $captured ) );
		if ( '' === $chunk ) {
			break;
		}
		$captured .= $chunk;
	}
}
echo base64_encode( $captured ) . "\n";
flush();

if ( 'respond' === $mode ) {
	$response = base64_decode( $response_b64, true );
	if ( false !== $response ) {
		if ( strlen( $captured ) >= 2 ) {
			$response = str_replace( "\xAA\xBB", substr( $captured, 0, 2 ), $response );
		}
		fwrite( $conn, pack( 'n', strlen( $response ) ) . $response );
	}
}

fclose( $conn );
fclose( $server );
