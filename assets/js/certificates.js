/**
 * TLS Certificates (ACME) admin page JavaScript.
 * Form-only behaviour for includes/admin/views/page-certificates.php:
 * provider/deployment/challenge-type field visibility and the key-type
 * keygen-command hint. No AJAX, no dynamic PHP data -- kept out of the
 * shared wp-sam-admin bundle so this self-contained page's script stays
 * self-contained too.
 */
( function () {
	'use strict';

	var providerSelect = document.getElementById( 'wp_sam_cert_provider' );
	var deploySelect   = document.getElementById( 'wp_sam_cert_deployment' );

	// Only the visible provider's inputs may carry a name= (so unrelated
	// blank password fields never submit); hidden ones park it in data-cred-name.
	function syncProvider() {
		document.querySelectorAll( '.wp-sam-cert-provider-fields' ).forEach( function ( row ) {
			var active = row.dataset.provider === providerSelect.value;
			row.style.display = active ? '' : 'none';
			row.querySelectorAll( 'input, textarea' ).forEach( function ( input ) {
				if ( active && input.dataset.credName ) {
					input.name = input.dataset.credName;
				} else if ( ! active && input.name ) {
					input.dataset.credName = input.name;
					input.removeAttribute( 'name' );
				}
			} );
		} );
	}

	function syncDeploy() {
		document.querySelectorAll( '.wp-sam-cert-deploy-fields' ).forEach( function ( row ) {
			row.style.display = row.dataset.deployment === deploySelect.value ? '' : 'none';
		} );
	}

	// DNS-01 <-> HTTP-01 toggle: the provider dropdown and its credential
	// rows only apply to DNS-01. Stored provider credentials are kept when
	// switching to HTTP-01 -- hiding is display-only.
	function syncChallenge() {
		var picked = document.querySelector( 'input[name="wp_sam_cert_challenge"]:checked' );
		var isDns  = ! picked || picked.value === 'dns-01';
		document.querySelectorAll( '.wp-sam-cert-dns-only' ).forEach( function ( row ) {
			row.style.display = isDns ? '' : 'none';
		} );
		if ( isDns ) {
			syncProvider(); // Re-apply per-provider visibility within the DNS rows.
		}
	}

	if ( providerSelect ) {
		providerSelect.addEventListener( 'change', syncProvider );
		syncProvider();
	}
	if ( deploySelect ) {
		deploySelect.addEventListener( 'change', syncDeploy );
		syncDeploy();
	}
	document.querySelectorAll( 'input[name="wp_sam_cert_challenge"]' ).forEach( function ( radio ) {
		radio.addEventListener( 'change', syncChallenge );
	} );
	syncChallenge();

	// Show the openssl key-generation command matching the selected key type.
	function syncKeygenCmd() {
		var picked = document.querySelector( 'input[name="wp_sam_cert_key_type"]:checked' );
		var type   = picked ? picked.value : 'ec-256';
		document.querySelectorAll( '.wp-sam-cert-keygen-cmd' ).forEach( function ( p ) {
			p.style.display = p.dataset.keytype === type ? '' : 'none';
		} );
	}
	document.querySelectorAll( 'input[name="wp_sam_cert_key_type"]' ).forEach( function ( radio ) {
		radio.addEventListener( 'change', syncKeygenCmd );
	} );
	syncKeygenCmd();
} )();
