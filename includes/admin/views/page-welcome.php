<?php
/**
 * Admin view: Welcome / Personal Preferences.
 *
 * Per the Customer-Centred Administration Experience specification §4: this
 * page collects ONLY personal presentation preferences for the current
 * WordPress user. It contains no security-control toggle, no automation
 * setting, no enforcement setting, no policy or certificate configuration,
 * and no other site-wide behavioural configuration -- saving or skipping it
 * changes what this one user sees, never how the site is protected.
 *
 * Serves both the first-run welcome screen and the "edit later" Personal
 * Preferences page -- same fields and wording either way (spec §6); only the
 * intro copy differs, controlled by $is_first_run.
 *
 * Rendered by Admin_UI::render_welcome().
 *
 * @var bool  $is_first_run
 * @var array $wp_sam_prefs Presentation_Preferences::get_for_user() result.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$action_url = admin_url( 'admin-post.php' );
?>
<div class="wrap wp-sam-wrap wp-sam-welcome">
	<h1>
		<?php
		echo esc_html(
			$is_first_run
				? __( 'Welcome to Security Automation Manager', 'vcns-security-automation-manager' )
				: __( 'Personal Preferences', 'vcns-security-automation-manager' )
		);
		?>
	</h1>

	<p>
		<?php esc_html_e( 'Tell SAM how you would like security information presented to you. These preferences only change what you see and how information is explained. They do not change how your website is protected.', 'vcns-security-automation-manager' ); ?>
	</p>

	<p class="description">
		<?php esc_html_e( 'This page does not contain security-control toggles, automation settings, enforcement settings, or any other site-wide configuration -- those remain on the Settings, Observe, Decide, Control and Verify pages, unaffected by anything here.', 'vcns-security-automation-manager' ); ?>
	</p>

	<form method="post" action="<?php echo esc_url( $action_url ); ?>">
		<?php wp_nonce_field( 'wp_sam_save_presentation_preferences' ); ?>
		<input type="hidden" name="action" value="wp_sam_save_presentation_preferences" />

		<fieldset class="wp-sam-welcome-question">
			<legend><strong><?php esc_html_e( 'What is your relationship to this website?', 'vcns-security-automation-manager' ); ?></strong></legend>
			<?php
			$relationship_options = array(
				'owner_manager'  => __( 'I own or manage the business/organisation', 'vcns-security-automation-manager' ),
				'site_admin'     => __( 'I administer or manage the website', 'vcns-security-automation-manager' ),
				'developer'      => __( 'I develop or technically maintain the website', 'vcns-security-automation-manager' ),
				'content_editor' => __( 'I create or edit content', 'vcns-security-automation-manager' ),
				'client_sites'   => __( 'I manage websites for clients', 'vcns-security-automation-manager' ),
				'other'          => __( 'Other / not sure', 'vcns-security-automation-manager' ),
			);
			foreach ( $relationship_options as $value => $label ) :
				$id = 'wp_sam_relationship_' . $value;
				?>
				<p>
					<label for="<?php echo esc_attr( $id ); ?>">
						<input type="radio" id="<?php echo esc_attr( $id ); ?>" name="relationship" value="<?php echo esc_attr( $value ); ?>" <?php checked( $wp_sam_prefs['relationship'], $value ); ?> />
						<?php echo esc_html( $label ); ?>
					</label>
				</p>
			<?php endforeach; ?>
		</fieldset>

		<fieldset class="wp-sam-welcome-question">
			<legend><strong><?php esc_html_e( 'How familiar are you with website security?', 'vcns-security-automation-manager' ); ?></strong></legend>
			<?php
			$familiarity_options = array(
				'new'         => __( 'New to it', 'vcns-security-automation-manager' ),
				'comfortable' => __( 'Comfortable with the basics', 'vcns-security-automation-manager' ),
				'experienced' => __( 'Experienced', 'vcns-security-automation-manager' ),
				'specialist'  => __( 'Security specialist', 'vcns-security-automation-manager' ),
			);
			foreach ( $familiarity_options as $value => $label ) :
				$id = 'wp_sam_familiarity_' . $value;
				?>
				<p>
					<label for="<?php echo esc_attr( $id ); ?>">
						<input type="radio" id="<?php echo esc_attr( $id ); ?>" name="security_familiarity" value="<?php echo esc_attr( $value ); ?>" <?php checked( $wp_sam_prefs['security_familiarity'], $value ); ?> />
						<?php echo esc_html( $label ); ?>
					</label>
				</p>
			<?php endforeach; ?>
		</fieldset>

		<fieldset class="wp-sam-welcome-question">
			<legend><strong><?php esc_html_e( 'How would you like SAM to present security information?', 'vcns-security-automation-manager' ); ?></strong></legend>
			<?php
			$depth_options = array(
				'simple'    => array(
					'label'       => __( 'Simple', 'vcns-security-automation-manager' ),
					'description' => __( 'Focus on whether the site is protected, what needs attention and what you should do next.', 'vcns-security-automation-manager' ),
				),
				'balanced'  => array(
					'label'       => __( 'Balanced', 'vcns-security-automation-manager' ),
					'description' => __( 'Show clear security outcomes with enough technical information to understand why.', 'vcns-security-automation-manager' ),
				),
				'technical' => array(
					'label'       => __( 'Technical', 'vcns-security-automation-manager' ),
					'description' => __( 'Prioritise technical state, evidence, policy detail and direct access to advanced information.', 'vcns-security-automation-manager' ),
				),
			);
			foreach ( $depth_options as $value => $option ) :
				$id = 'wp_sam_depth_' . $value;
				?>
				<p>
					<label for="<?php echo esc_attr( $id ); ?>">
						<input type="radio" id="<?php echo esc_attr( $id ); ?>" name="presentation_depth" value="<?php echo esc_attr( $value ); ?>" <?php checked( $wp_sam_prefs['presentation_depth'], $value ); ?> />
						<strong><?php echo esc_html( $option['label'] ); ?></strong> -- <?php echo esc_html( $option['description'] ); ?>
					</label>
				</p>
			<?php endforeach; ?>
		</fieldset>

		<fieldset class="wp-sam-welcome-question">
			<legend><strong><?php esc_html_e( 'What would you most like SAM to show you first?', 'vcns-security-automation-manager' ); ?></strong></legend>
			<?php
			$landing_options = array(
				'overall'    => __( 'Overall security status', 'vcns-security-automation-manager' ),
				'attention'  => __( 'Items needing my attention', 'vcns-security-automation-manager' ),
				'activity'   => __( 'Recent security activity', 'vcns-security-automation-manager' ),
				'protection' => __( 'Protection status', 'vcns-security-automation-manager' ),
				'technical'  => __( 'Technical overview', 'vcns-security-automation-manager' ),
				'none'       => __( 'No preference', 'vcns-security-automation-manager' ),
			);
			foreach ( $landing_options as $value => $label ) :
				$id = 'wp_sam_landing_' . $value;
				?>
				<p>
					<label for="<?php echo esc_attr( $id ); ?>">
						<input type="radio" id="<?php echo esc_attr( $id ); ?>" name="landing_emphasis" value="<?php echo esc_attr( $value ); ?>" <?php checked( $wp_sam_prefs['landing_emphasis'], $value ); ?> />
						<?php echo esc_html( $label ); ?>
					</label>
				</p>
			<?php endforeach; ?>
		</fieldset>

		<p class="wp-sam-welcome-actions">
			<button type="submit" name="wp_sam_action" value="save" class="button button-primary">
				<?php esc_html_e( 'Save my preferences', 'vcns-security-automation-manager' ); ?>
			</button>
			<?php if ( $is_first_run ) : ?>
				<button type="submit" name="wp_sam_action" value="skip" class="button button-secondary" formnovalidate="formnovalidate">
					<?php esc_html_e( 'Skip for now', 'vcns-security-automation-manager' ); ?>
				</button>
			<?php endif; ?>
		</p>
	</form>
</div>
