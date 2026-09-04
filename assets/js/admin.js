/**
 * Security Automation Manager admin JavaScript.
 * Handles AJAX interactions on the plugin's admin pages.
 */
/* global wpSamAdmin, jQuery */
( function ( $ ) {
	'use strict';

	$( '#wp-sam-manual-scan' ).on( 'click', function () {
		const $btn    = $( this );
		const $status = $( '#wp-sam-scan-status' );

		$btn.prop( 'disabled', true );
		$status.text( wpSamAdmin.i18n.scanning ).show();

		$.post( wpSamAdmin.ajaxUrl, {
			action: 'wp_sam_manual_scan',
			nonce:  wpSamAdmin.nonce,
		} )
		.done( function ( res ) {
			if ( res.success ) {
				$status.text( wpSamAdmin.i18n.scanDone );
				setTimeout( function () { location.reload(); }, 1500 );
			} else {
				$status.text( res.data.message || wpSamAdmin.i18n.scanError );
			}
		} )
		.fail( function () {
			$status.text( wpSamAdmin.i18n.scanError );
		} )
		.always( function () {
			$btn.prop( 'disabled', false );
		} );
	} );

	$( '.wp-sam-toggle-mode' ).on( 'click', function () {
		const $btn    = $( this );
		const surface = $btn.data( 'surface' );
		const mode    = $btn.data( 'mode' );

		$btn.prop( 'disabled', true );

		$.post( wpSamAdmin.ajaxUrl, {
			action:  'wp_sam_toggle_mode',
			nonce:   wpSamAdmin.nonce,
			surface: surface,
			mode:    mode,
		} )
		.done( function ( res ) {
			if ( res.success ) {
				location.reload();
			} else {
				// eslint-disable-next-line no-alert
				alert( res.data.message || 'Failed to switch mode.' );
				$btn.prop( 'disabled', false );
			}
		} )
		.fail( function () {
			$btn.prop( 'disabled', false );
		} );
	} );

	$( '.wp-sam-bypass-flag-toggle' ).on( 'change', function () {
		const $checkbox = $( this );
		const surface   = $checkbox.data( 'surface' );
		const flag      = $checkbox.data( 'flag' );
		const enabled   = $checkbox.is( ':checked' );

		$checkbox.prop( 'disabled', true );

		$.post( wpSamAdmin.ajaxUrl, {
			action:  'wp_sam_set_bypass_flag',
			nonce:   wpSamAdmin.nonce,
			surface: surface,
			flag:    flag,
			enabled: enabled ? 1 : 0,
		} )
		.done( function ( res ) {
			if ( ! res || true !== res.success ) {
				$checkbox.prop( 'checked', ! enabled );
				// eslint-disable-next-line no-alert
				alert( ( res && res.data && res.data.message ) || 'Failed to save.' );
			}
		} )
		.fail( function () {
			$checkbox.prop( 'checked', ! enabled );
		} )
		.always( function () {
			$checkbox.prop( 'disabled', false );
		} );
	} );

	$( '.wp-sam-trusted-types-toggle' ).on( 'change', function () {
		const $checkbox = $( this );
		const surface   = $checkbox.data( 'surface' );
		const enabled   = $checkbox.is( ':checked' );

		$checkbox.prop( 'disabled', true );

		$.post( wpSamAdmin.ajaxUrl, {
			action:  'wp_sam_set_trusted_types',
			nonce:   wpSamAdmin.nonce,
			surface: surface,
			enabled: enabled ? 1 : 0,
		} )
		.done( function ( res ) {
			if ( ! res || true !== res.success ) {
				$checkbox.prop( 'checked', ! enabled );
				// eslint-disable-next-line no-alert
				alert( ( res && res.data && res.data.message ) || 'Failed to save.' );
			}
		} )
		.fail( function () {
			$checkbox.prop( 'checked', ! enabled );
		} )
		.always( function () {
			$checkbox.prop( 'disabled', false );
		} );
	} );

	$( '.wp-sam-automation-mode' ).on( 'change', function () {
		const $select = $( this );
		const surface = $select.data( 'surface' );
		const mode    = $select.val();
		const previous = $select.data( 'previous' ) || '';

		$select.prop( 'disabled', true );

		$.post( wpSamAdmin.ajaxUrl, {
			action:  'wp_sam_set_automation_mode',
			nonce:   wpSamAdmin.nonce,
			surface: surface,
			mode:    mode,
		} )
		.done( function ( res ) {
			if ( res.success ) {
				$select.data( 'previous', mode );
				return;
			}

			if ( previous !== '' ) {
				$select.val( previous );
			}
			// eslint-disable-next-line no-alert
			alert( res.data.message || 'Failed to switch automation mode.' );
		} )
		.fail( function () {
			if ( previous !== '' ) {
				$select.val( previous );
			}
			// eslint-disable-next-line no-alert
			alert( 'Failed to switch automation mode.' );
		} )
		.always( function () {
			$select.prop( 'disabled', false );
		} );
	} ).each( function () {
		$( this ).data( 'previous', $( this ).val() );
	} );

	/**
	 * WordPress returns HTTP 200 for a real success, a check_ajax_referer()
	 * nonce failure (body "-1"), and a wp_send_json_error() validation error
	 * alike -- none of those are network failures jQuery's .fail() catches.
	 * Autosave handlers below must inspect the response body in .done()
	 * rather than assuming HTTP 200 means saved, or a failure silently
	 * re-enables the control with nothing actually written.
	 */
	function reportAjaxFailure( res ) {
		if ( res && true === res.success ) {
			return;
		}
		// eslint-disable-next-line no-alert
		alert( ( res && res.data && res.data.message ) || 'Failed to save.' );
	}

	function requiredReason( promptText ) {
		const reason = window.prompt( promptText, '' );
		if ( reason === null ) {
			return null;
		}
		if ( reason.trim() === '' ) {
			// eslint-disable-next-line no-alert
			alert( wpSamAdmin.i18n.reasonRequired || 'A decision reason is required.' );
			return null;
		}
		return reason.trim();
	}

	function sourceActionsHtml( id, state, lastDecision ) {
		const buttons = [];
		if ( state === 'pending' || state === 'denied' ) {
			buttons.push( '<button type="button" class="button button-small wp-sam-approve-source" data-id="' + id + '">Approve</button>' );
		}
		if ( state === 'pending' || state === 'approved' ) {
			buttons.push( '<button type="button" class="button button-small wp-sam-deny-source" data-id="' + id + '">Reject</button>' );
		}
		if ( state === 'approved' ) {
			buttons.push( '<button type="button" class="button button-small wp-sam-revert-source" data-id="' + id + '">Revert</button>' );
		}
		if ( lastDecision === 'approved' || lastDecision === 'rejected' ) {
			buttons.push( '<button type="button" class="button button-small wp-sam-undo-source-decision" data-id="' + id + '">Undo</button>' );
		}
		return buttons.join( ' ' );
	}

	function setSourceRowState( $row, id, state, label, lastDecision ) {
		$row.find( '.wp-sam-state-badge' )
			.removeClass( 'state-pending state-approved state-denied' )
			.addClass( 'state-' + state )
			.text( label );
		$row.find( '.wp-sam-source-actions' ).html( sourceActionsHtml( id, state, lastDecision ) );
	}

	function postSourceDecision( $btn, action, promptText, nextState, nextLabel, lastDecision ) {
		const id     = $btn.data( 'id' );
		const reason = requiredReason( promptText );
		if ( reason === null ) {
			return;
		}

		$btn.prop( 'disabled', true );

		$.post( wpSamAdmin.ajaxUrl, {
			action:    action,
			nonce:     wpSamAdmin.nonce,
			source_id: id,
			reason:    reason,
		} )
		.done( function ( res ) {
			if ( res.success ) {
				setSourceRowState( $btn.closest( 'tr' ), id, nextState, nextLabel, lastDecision );
			} else {
				// eslint-disable-next-line no-alert
				alert( res.data.message || 'Could not record policy decision.' );
			}
		} )
		.fail( function () {
			// eslint-disable-next-line no-alert
			alert( 'Could not record policy decision.' );
		} )
		.always( function () { $btn.prop( 'disabled', false ); } );
	}

	$( document ).on( 'click', '.wp-sam-approve-source', function () {
		postSourceDecision( $( this ), 'wp_sam_approve_source', 'Why should this source be approved?', 'approved', 'Approved', 'approved' );
	} );

	$( document ).on( 'click', '.wp-sam-deny-source', function () {
		postSourceDecision( $( this ), 'wp_sam_deny_source', 'Why should this source be rejected and suppressed?', 'denied', 'Denied', 'rejected' );
	} );

	$( document ).on( 'click', '.wp-sam-revert-source', function () {
		postSourceDecision( $( this ), 'wp_sam_revert_source', 'Why should this approved source be reverted and suppressed?', 'denied', 'Denied', 'reverted' );
	} );

	$( document ).on( 'click', '.wp-sam-undo-source-decision', function () {
		postSourceDecision( $( this ), 'wp_sam_undo_source_decision', 'Why should this decision be undone?', 'pending', 'Pending', 'undone' );
	} );

	$( document ).on( 'click', '.wp-sam-use-current-report-endpoint', function () {
		$( '#wp_sam_report_endpoint_url' )
			.val( $( this ).data( 'report-endpoint' ) || '' )
			.trigger( 'change' );
	} );

	function postPillarValue( $control ) {
		const $row     = $control.closest( 'tr' );
		const pillar   = $control.data( 'pillar' );
		const surface  = $control.data( 'surface' );
		const $mode    = $row.find( '.wp-sam-pillar-mode' );
		const hasMode  = $mode.length > 0;
		const mode     = hasMode ? ( $mode.val() || '' ) : '';
		// Pillars with a mode selector (currently COOP/COEP) derive "enabled"
		// from the mode instead of a separate checkbox -- the mode select
		// replaces that checkbox entirely for those two.
		const enabled  = hasMode ? ( 'disabled' !== mode ) : $row.find( '.wp-sam-pillar-enabled' ).is( ':checked' );
		const value    = $row.find( '.wp-sam-pillar-value' ).val() || '';
		const $fields  = $row.find( '.wp-sam-pillar-enabled, .wp-sam-pillar-value, .wp-sam-pillar-mode' );

		$fields.prop( 'disabled', true );

		$.post( wpSamAdmin.ajaxUrl, {
			action:  'wp_sam_set_pillar_value',
			nonce:   wpSamAdmin.nonce,
			pillar:  pillar,
			surface: surface,
			enabled: enabled ? '1' : '',
			value:   value,
			mode:    mode,
		} )
		.done( reportAjaxFailure )
		.fail( function () {
			// eslint-disable-next-line no-alert
			alert( 'Failed to save.' );
		} )
		.always( function () {
			$fields.prop( 'disabled', false );
		} );
	}

	$( document ).on( 'change', '.wp-sam-pillar-enabled, .wp-sam-pillar-value, .wp-sam-pillar-mode', function () {
		postPillarValue( $( this ) );
	} );

	function postPermissionsPolicyChange( $control ) {
		const $row      = $control.closest( 'tr' );
		const surface   = $row.find( '.wp-sam-permissions-policy-enabled' ).data( 'surface' );
		const enabled   = $row.find( '.wp-sam-permissions-policy-enabled' ).is( ':checked' );
		const isSelect  = $control.hasClass( 'wp-sam-permissions-policy-directive' );
		const directive = isSelect ? $control.data( 'directive' ) : '';
		const value     = isSelect ? $control.val() : '';

		$row.find( '.wp-sam-permissions-policy-enabled, .wp-sam-permissions-policy-directive' ).prop( 'disabled', true );

		$.post( wpSamAdmin.ajaxUrl, {
			action:    'wp_sam_set_permissions_policy_directive',
			nonce:     wpSamAdmin.nonce,
			surface:   surface,
			enabled:   enabled ? '1' : '',
			directive: directive,
			value:     value,
		} )
		.done( reportAjaxFailure )
		.fail( function () {
			// eslint-disable-next-line no-alert
			alert( 'Failed to save.' );
		} )
		.always( function () {
			$row.find( '.wp-sam-permissions-policy-enabled, .wp-sam-permissions-policy-directive' ).prop( 'disabled', false );
		} );
	}

	$( document ).on( 'change', '.wp-sam-permissions-policy-enabled, .wp-sam-permissions-policy-directive', function () {
		postPermissionsPolicyChange( $( this ) );
	} );

	const HSTS_PRELOAD_MIN_MAX_AGE = 31536000; // 1 year -- mirrors Strict_Transport_Security_Builder::PRELOAD_MIN_MAX_AGE.

	function refreshHstsPreloadEligibility( $row ) {
		const maxAge            = parseInt( $row.find( '.wp-sam-hsts-max-age' ).val(), 10 ) || 0;
		const includeSubdomains = $row.find( '.wp-sam-hsts-include-subdomains' ).is( ':checked' );
		const $preload          = $row.find( '.wp-sam-hsts-preload' );
		const eligible          = includeSubdomains && maxAge >= HSTS_PRELOAD_MIN_MAX_AGE;

		$preload.prop( 'disabled', ! eligible );
		if ( ! eligible ) {
			$preload.prop( 'checked', false );
		}
	}

	function postHstsChange( $control ) {
		const $row = $control.closest( 'tr' );

		refreshHstsPreloadEligibility( $row );

		const surface            = $row.find( '.wp-sam-hsts-enabled' ).data( 'surface' );
		const enabled             = $row.find( '.wp-sam-hsts-enabled' ).is( ':checked' );
		const maxAge              = $row.find( '.wp-sam-hsts-max-age' ).val();
		const includeSubdomains   = $row.find( '.wp-sam-hsts-include-subdomains' ).is( ':checked' );
		const preload             = $row.find( '.wp-sam-hsts-preload' ).is( ':checked' );

		$row.find( 'input, select' ).prop( 'disabled', true );

		$.post( wpSamAdmin.ajaxUrl, {
			action:              'wp_sam_set_hsts',
			nonce:                wpSamAdmin.nonce,
			surface:              surface,
			enabled:              enabled ? '1' : '',
			max_age:              maxAge,
			include_subdomains:   includeSubdomains ? '1' : '',
			preload:              preload ? '1' : '',
		} )
		.done( reportAjaxFailure )
		.fail( function () {
			// eslint-disable-next-line no-alert
			alert( 'Failed to save.' );
		} )
		.always( function () {
			$row.find( 'input, select' ).prop( 'disabled', false );
			refreshHstsPreloadEligibility( $row );
		} );
	}

	$( document ).on( 'change', '.wp-sam-hsts-enabled, .wp-sam-hsts-max-age, .wp-sam-hsts-include-subdomains, .wp-sam-hsts-preload', function () {
		postHstsChange( $( this ) );
	} );

	function postDependencyMode( $control ) {
		const $row     = $control.closest( 'tr' );
		const surface  = $row.find( '.wp-sam-dependency-enabled' ).data( 'surface' );
		const enabled  = $row.find( '.wp-sam-dependency-enabled' ).is( ':checked' );
		const mode     = $row.find( '.wp-sam-dependency-mode' ).val();

		$row.find( 'input, select' ).prop( 'disabled', true );

		$.post( wpSamAdmin.ajaxUrl, {
			action:  'wp_sam_set_dependency_mode',
			nonce:   wpSamAdmin.nonce,
			surface: surface,
			enabled: enabled ? '1' : '',
			mode:    mode,
		} )
		.done( reportAjaxFailure )
		.fail( function () {
			// eslint-disable-next-line no-alert
			alert( 'Failed to save.' );
		} )
		.always( function () {
			$row.find( 'input, select' ).prop( 'disabled', false );
		} );
	}

	$( document ).on( 'change', '.wp-sam-dependency-enabled, .wp-sam-dependency-mode', function () {
		postDependencyMode( $( this ) );
	} );

	function refreshSriInputState( $row ) {
		const classification = $row.find( '.wp-sam-dependency-classification' ).val();
		const disabled       = 'immutable_pinned' !== classification;
		$row.find( '.wp-sam-dependency-sri' ).prop( 'disabled', disabled );
		$row.find( '.wp-sam-dependency-suggest-url, .wp-sam-dependency-suggest-button' ).prop( 'disabled', disabled );
	}

	function postDependencyClassification( $row ) {
		const id             = $row.find( '.wp-sam-dependency-classification' ).data( 'id' );
		const classification = $row.find( '.wp-sam-dependency-classification' ).val();
		const expectedSri    = $row.find( '.wp-sam-dependency-sri' ).val();

		$.post( wpSamAdmin.ajaxUrl, {
			action:         'wp_sam_classify_dependency',
			nonce:           wpSamAdmin.nonce,
			id:              id,
			classification:  classification,
			expected_sri:    expectedSri,
		} )
		.done( reportAjaxFailure )
		.fail( function () {
			// eslint-disable-next-line no-alert
			alert( 'Failed to save.' );
		} );
	}

	$( document ).on( 'change', '.wp-sam-dependency-classification', function () {
		const $row = $( this ).closest( 'tr' );
		refreshSriInputState( $row );
		postDependencyClassification( $row );
	} );

	$( document ).on( 'change', '.wp-sam-dependency-sri', function () {
		postDependencyClassification( $( this ).closest( 'tr' ) );
	} );

	$( document ).on( 'click', '.wp-sam-dependency-suggest-button', function () {
		const $button = $( this );
		const $row    = $button.closest( 'tr' );
		const id      = $button.data( 'id' );
		const url     = $row.find( '.wp-sam-dependency-suggest-url' ).val();

		if ( ! url ) {
			// eslint-disable-next-line no-alert
			alert( 'Enter the exact URL to fetch and hash first.' );
			return;
		}

		const originalLabel = $button.text();
		$button.prop( 'disabled', true ).text( '…' );

		$.post( wpSamAdmin.ajaxUrl, {
			action: 'wp_sam_suggest_dependency_sri',
			nonce:  wpSamAdmin.nonce,
			id:     id,
			url:    url,
		} )
		.done( function ( res ) {
			if ( res.success && res.data && res.data.hash ) {
				$row.find( '.wp-sam-dependency-sri' ).val( res.data.hash );
				postDependencyClassification( $row );
			} else {
				// eslint-disable-next-line no-alert
				alert( ( res.data && res.data.message ) || 'Could not compute a hash for that URL.' );
			}
		} )
		.fail( function () {
			// eslint-disable-next-line no-alert
			alert( 'Failed to compute hash.' );
		} )
		.always( function () {
			$button.prop( 'disabled', false ).text( originalLabel );
		} );
	} );

	$( document ).on( 'click', '.wp-sam-upgrade-button', function () {
		const $button  = $( this );
		const $status  = $( '#wp-sam-upgrade-status' );
		const interval = $button.data( 'interval' ) || 'monthly';

		$( '.wp-sam-upgrade-button' ).prop( 'disabled', true );
		$status.text( wpSamAdmin.i18n.upgradeStarting || 'Starting checkout…' );

		$.post( wpSamAdmin.ajaxUrl, {
			action:   'wp_sam_create_checkout_session',
			nonce:    wpSamAdmin.nonce,
			interval: interval,
		} )
		.done( function ( res ) {
			if ( res.success && res.data.url ) {
				window.location.href = res.data.url;
				return;
			}
			$status.text( ( res.data && res.data.message ) || 'Unable to start checkout.' );
			$( '.wp-sam-upgrade-button' ).prop( 'disabled', false );
		} )
		.fail( function () {
			$status.text( 'Unable to start checkout.' );
			$( '.wp-sam-upgrade-button' ).prop( 'disabled', false );
		} );
	} );

	// Custom Rules tab: "Test a pattern" tool -- Traffic Controls -> Custom Rules.
	$( '#wp-sam-custom-rule-test-button' ).on( 'click', function () {
		const $btn     = $( this );
		const $result  = $( '#wp-sam-custom-rule-test-result' );
		const pattern  = $( '#wp_sam_cr_test_pattern' ).val();
		const sample   = $( '#wp_sam_cr_test_sample' ).val();

		$btn.prop( 'disabled', true );
		$result.text( '' ).css( 'color', '' );

		$.post( wpSamAdmin.ajaxUrl, {
			action:  'wp_sam_test_custom_rule',
			nonce:   wpSamAdmin.nonce,
			pattern: pattern,
			sample:  sample,
		} )
		.done( function ( res ) {
			if ( ! res.success ) {
				$result.text( 'Request failed.' ).css( 'color', '#cc1818' );
				return;
			}
			const matched = res.data.matched;
			if ( null === matched ) {
				$result.text( 'Invalid pattern.' ).css( 'color', '#cc1818' );
			} else if ( matched ) {
				$result.text( 'Matches.' ).css( 'color', '#1a7f37' );
			} else {
				$result.text( 'Does not match.' ).css( 'color', '#646970' );
			}
		} )
		.fail( function () {
			$result.text( 'Request failed.' ).css( 'color', '#cc1818' );
		} )
		.always( function () {
			$btn.prop( 'disabled', false );
		} );
	} );
} )( jQuery );
