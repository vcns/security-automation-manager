// Browser checks (c-f) for one matrix environment. run.sh calls this after
// WordPress is installed and SAM is active; it writes browser.json,
// checks.tsv lines and screenshots into --out.
//
//   node checks.mjs --base=http://localhost:8726 --wp=7.2-RC3 --out=results/7.2-8.6
//                   --project=sam-7-2-8-6 --compose=docker-compose.yml --hidden=slug,slug
//
// Every request carries X-Forwarded-For: CLIENT_IP, which mod_remoteip in
// the container puts into REMOTE_ADDR (see Dockerfile), so SAM sees a
// public visitor rather than the Docker gateway's private address.

import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const opts = Object.fromEntries(
	process.argv.slice(2).map((a) => {
		const [k, ...v] = a.replace(/^--/, '').split('=');
		return [k, v.join('=')];
	})
);

const BASE = opts.base;
const OUT = path.resolve(opts.out);
const WP = opts.wp;
const PROJECT = opts.project;
const COMPOSE = opts.compose;
const HIDDEN = (opts.hidden || '').split(',').filter(Boolean);
const IS_72 = WP.startsWith('7.2');
const CLIENT_IP = '198.51.100.23';
const PLUGIN_PATH = '/wp-content/plugins/security-automation-manager/';
const ADMIN = { user: 'admin', pass: 'matrix-admin-pass' };
const EDITOR = { user: 'editor', pass: 'matrix-editor-pass' };
const STAGES = [
	['Settings', 'security-automation-manager'],
	['Observe', 'security-automation-manager-observe'],
	['Decide', 'security-automation-manager-decide'],
	['Control', 'security-automation-manager-control'],
	['Verify', 'security-automation-manager-verify'],
];

fs.mkdirSync(path.join(OUT, 'screenshots'), { recursive: true });
const checks = [];
const result = { base: BASE, wp: WP, client_ip: CLIENT_IP };

// ── Docker helpers ─────────────────────────────────────────────────────────

const dockerEnv = { ...process.env, MSYS_NO_PATHCONV: '1' };

function compose(args, input) {
	return execFileSync('docker', ['compose', '-p', PROJECT, '-f', COMPOSE, '--profile', 'cli', ...args], {
		encoding: 'utf8',
		env: dockerEnv,
		input,
		stdio: ['pipe', 'pipe', 'pipe'],
		maxBuffer: 512 * 1024 * 1024,
	});
}

function sql(query) {
	return compose(['exec', '-T', 'db', 'mysql', '-N', '-B', '-uwordpress', '-pwordpress', 'wordpress', '-e', query]).trim();
}

function sqlRows(query) {
	const out = sql(query);
	return out === '' ? [] : out.split('\n').map((l) => l.split('\t'));
}

function attachmentCount() {
	return Number(sql("SELECT COUNT(*) FROM wp_posts WHERE post_type='attachment'"));
}

function reportPosts() {
	const log = compose(['logs', '--no-log-prefix', 'wordpress']);
	return (log.match(/"POST \/wp-json\/sam\/v1\/report/g) || []).length;
}

async function waitFor(fn, timeoutMs, stepMs = 1000) {
	const end = Date.now() + timeoutMs;
	while (Date.now() < end) {
		if (fn()) return true;
		await new Promise((r) => setTimeout(r, stepMs));
	}
	return fn();
}

function check(id, status, detail) {
	checks.push([id, status, String(detail).replace(/[\t\n]+/g, ' ')]);
}

// ── Browser helpers ────────────────────────────────────────────────────────

const browser = await chromium.launch();
result.browser = `chromium ${browser.version()}`;

async function newContext() {
	const ctx = await browser.newContext({
		viewport: { width: 1440, height: 900 },
		deviceScaleFactor: 1,
		extraHTTPHeaders: { 'X-Forwarded-For': CLIENT_IP },
	});
	// JQMIGRATE warnings come from jquery-migrate.js itself, so the caller
	// is only visible in a stack captured at the console.warn call.
	await ctx.addInitScript(() => {
		window.__samCsp = [];
		document.addEventListener('securitypolicyviolation', (e) => {
			window.__samCsp.push({ directive: e.effectiveDirective, blocked: String(e.blockedURI).slice(0, 120), disposition: e.disposition });
		});
		window.__samJqmigrate = [];
		const warn = console.warn;
		console.warn = function (...args) {
			try {
				const msg = String(args[0] ?? '');
				if (msg.includes('JQMIGRATE')) {
					window.__samJqmigrate.push({ message: msg, stack: String(new Error().stack) });
				}
			} catch (e) {}
			return warn.apply(this, args);
		};
	});
	return ctx;
}

async function login(ctx, who) {
	const page = await ctx.newPage();
	await page.goto(`${BASE}/wp-login.php`);
	await page.fill('#user_login', who.user);
	await page.fill('#user_pass', who.pass);
	await Promise.all([page.waitForURL(/wp-admin/, { timeout: 60000 }), page.click('#wp-submit')]);
	await page.close();
}

function watch(page) {
	const sink = { console: [], pageerrors: [], http5xx: [] };
	page.on('console', (m) => {
		if (m.type() === 'error' || m.type() === 'warning') {
			sink.console.push({ type: m.type(), text: m.text().slice(0, 600), url: m.location()?.url || '' });
		}
	});
	page.on('pageerror', (e) => sink.pageerrors.push({ message: String(e.message).slice(0, 600), stack: String(e.stack || '').slice(0, 2000) }));
	page.on('response', (r) => {
		if (r.status() >= 500) sink.http5xx.push({ url: r.url().replace(BASE, ''), status: r.status() });
	});
	return sink;
}

const isCsp = (t) => /Content Security Policy|Content-Security-Policy/i.test(t);
const fromSam = (s) => String(s).includes(PLUGIN_PATH);

function shotName(url) {
	const u = new URL(url);
	const pageSlug = (u.searchParams.get('page') || path.basename(u.pathname, '.php')).replace('security-automation-manager', 'sam');
	const rest = [...u.searchParams.entries()].filter(([k]) => k !== 'page').map(([k, v]) => `${k}-${v}`).join('_');
	return `${pageSlug}${rest ? '_' + rest : ''}`.replace(/[^A-Za-z0-9_.-]+/g, '-').slice(0, 120) + '.png';
}

async function visit(page, sink, url, label) {
	sink.console.length = 0;
	sink.pageerrors.length = 0;
	sink.http5xx.length = 0;
	let status = 0;
	let error = '';
	try {
		const resp = await page.goto(url, { waitUntil: 'load', timeout: 90000 });
		status = resp ? resp.status() : 0;
		await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
	} catch (e) {
		error = String(e.message).slice(0, 300);
	}
	const h1 = await page.locator('#wpbody-content h1').count().catch(() => 0);
	const jqm = await page.evaluate(() => window.__samJqmigrate || []).catch(() => []);
	const shot = shotName(url);
	await page.screenshot({ path: path.join(OUT, 'screenshots', shot), fullPage: true }).catch(() => {});
	const samConsole = sink.console.filter((c) => c.type === 'error' && !isCsp(c.text) && (fromSam(c.url) || fromSam(c.text)));
	return {
		label,
		url: url.replace(BASE, ''),
		final_url: page.url().replace(BASE, ''),
		status,
		error,
		h1,
		sam_console_errors: samConsole,
		sam_page_errors: sink.pageerrors.filter((e) => fromSam(e.stack) || fromSam(e.message)),
		other_page_errors: sink.pageerrors.filter((e) => !(fromSam(e.stack) || fromSam(e.message))).length,
		sam_jqmigrate: jqm.filter((j) => fromSam(j.stack)),
		other_jqmigrate: jqm.filter((j) => !fromSam(j.stack)).map((j) => j.message),
		other_console_errors: sink.console.filter((c) => c.type === 'error' && !isCsp(c.text) && !(fromSam(c.url) || fromSam(c.text))).length,
		csp_console_messages: sink.console.filter((c) => isCsp(c.text)).length,
		http5xx: [...sink.http5xx],
		screenshot: shot,
	};
}

function samAdminLink(href) {
	try {
		const u = new URL(href);
		if (!u.pathname.endsWith('/wp-admin/admin.php')) return null;
		if (!(u.searchParams.get('page') || '').startsWith('security-automation-manager')) return null;
		// Never follow a link that performs an action rather than showing a page.
		if (/_wpnonce|nonce=|[?&](action|wp_sam_action|download|export|delete|run)=/i.test(u.search)) return null;
		u.hash = '';
		return u.toString();
	} catch {
		return null;
	}
}

// ── c) every SAM page, d) admin menu ───────────────────────────────────────

async function pagesAndMenu() {
	const ctx = await newContext();
	await login(ctx, ADMIN);
	const page = await ctx.newPage();
	const sink = watch(page);

	const queue = STAGES.map(([label, slug]) => [label, `${BASE}/wp-admin/admin.php?page=${slug}`]);
	const seen = new Set(queue.map(([, u]) => u));
	const pages = [];

	for (const [label, url] of queue.slice()) {
		pages.push(await visit(page, sink, url, `stage:${label}`));
		const hrefs = await page.$$eval('#wpbody-content a[href]', (as) => as.map((a) => a.href)).catch(() => []);
		for (const h of hrefs) {
			const link = samAdminLink(h);
			if (link && !seen.has(link)) {
				seen.add(link);
				queue.push([`linked from ${label}`, link]);
			}
		}
	}
	for (const [label, url] of queue.slice(STAGES.length)) {
		pages.push(await visit(page, sink, url, label));
	}
	for (const slug of HIDDEN) {
		const url = `${BASE}/wp-admin/admin.php?page=${slug}`;
		if (!seen.has(url)) {
			seen.add(url);
			pages.push(await visit(page, sink, url, 'hidden page'));
		}
	}
	result.pages = pages;

	const bad = pages.filter(
		(p) => p.status >= 500 || p.status === 0 || p.error || p.h1 === 0 || p.sam_console_errors.length || p.sam_page_errors.length || p.sam_jqmigrate.length || p.http5xx.length
	);
	check(
		'c',
		bad.length ? 'fail' : 'pass',
		`${pages.length} pages visited; ${bad.length} with a problem` +
			(bad.length ? ': ' + bad.slice(0, 8).map((p) => `${p.url} [status ${p.status}${p.h1 ? '' : ', no h1'}${p.sam_console_errors.length ? ', SAM console error' : ''}${p.sam_page_errors.length ? ', SAM page error' : ''}${p.sam_jqmigrate.length ? ', SAM JQMIGRATE' : ''}${p.http5xx.length ? ', 5xx subrequest' : ''}${p.error ? ', ' + p.error : ''}]`).join('; ') : '') +
			`. Non-SAM: ${pages.reduce((n, p) => n + p.other_console_errors, 0)} console errors, ${pages.reduce((n, p) => n + p.other_jqmigrate.length, 0)} JQMIGRATE warnings, ${pages.reduce((n, p) => n + p.csp_console_messages, 0)} CSP console messages.`
	);

	// d) Admin menu, read on the Settings page.
	await page.goto(`${BASE}/wp-admin/admin.php?page=security-automation-manager`);
	const menu = await page.evaluate((hidden) => {
		const top = document.querySelector('#toplevel_page_security-automation-manager');
		if (!top) return { found: false };
		const img = top.querySelector('.wp-menu-image');
		const cs = img ? getComputedStyle(img) : null;
		const before = img ? getComputedStyle(img, '::before') : null;
		const imgTag = img ? img.querySelector('img') : null;
		// WordPress 7.2 swaps a registered dashicon for an inline <svg>.
		const svgTag = img ? img.querySelector('svg') : null;
		const svgRect = svgTag ? svgTag.getBoundingClientRect() : { width: 0, height: 0 };
		const rect = img ? img.getBoundingClientRect() : { width: 0, height: 0 };
		const visible = [...top.querySelectorAll('.wp-submenu li')]
			.filter((li) => !li.classList.contains('wp-submenu-head') && getComputedStyle(li).display !== 'none')
			.map((li) => li.querySelector('a')?.childNodes[0]?.textContent.trim() || li.textContent.trim());
		return {
			found: true,
			icon: {
				class: img?.className || '',
				background_image: cs?.backgroundImage || '',
				before_content: before?.content || '',
				img_src: imgTag?.getAttribute('src')?.slice(0, 80) || '',
				inline_svg: svgTag ? `${Math.round(svgRect.width)}x${Math.round(svgRect.height)}` : '',
				dashicons_font_loaded: document.fonts.check('20px dashicons'),
				width: rect.width,
				height: rect.height,
			},
			visible_items: visible,
			hidden: hidden.map((slug) => {
				const a = top.querySelector(`.wp-submenu a[href$="page=${slug}"]`);
				return { slug, in_menu: !!a, hidden: a ? getComputedStyle(a.closest('li')).display === 'none' : null };
			}),
		};
	}, HIDDEN);
	await page.locator('#adminmenu').screenshot({ path: path.join(OUT, 'screenshots', 'admin-menu.png') }).catch(() => {});
	result.menu = menu;
	const glyph = (menu.icon?.before_content || '').replace(/^"|"$/g, '');
	const how = !menu.found
		? ''
		: menu.icon.inline_svg && menu.icon.inline_svg !== '0x0'
			? `inline svg ${menu.icon.inline_svg}`
			: glyph && !['none', 'normal'].includes(menu.icon.before_content) && menu.icon.dashicons_font_loaded
				? `dashicon U+${glyph.codePointAt(0).toString(16).toUpperCase()}`
				: menu.icon.background_image && menu.icon.background_image !== 'none'
					? 'background image'
					: menu.icon.img_src
						? 'img'
						: '';
	const iconOk = menu.found && menu.icon.width > 0 && how !== '';
	const itemsOk = menu.found && JSON.stringify(menu.visible_items) === JSON.stringify(STAGES.map(([l]) => l));
	const hiddenOk = menu.found && menu.hidden.every((h) => h.hidden !== false);
	check(
		'd',
		iconOk && itemsOk && hiddenOk ? 'pass' : 'fail',
		`icon ${iconOk ? `renders (${how}, class ${menu.icon.class})` : `MISSING (class ${menu.icon?.class})`}; visible items: ${(menu.visible_items || []).join(', ')}; hidden slugs in menu ${menu.hidden?.filter((h) => h.in_menu).length}/${HIDDEN.length}, all hidden: ${hiddenOk}`
	);
	await ctx.close();
}

// ── e) WP 7.2 client-side media under the admin CSP ────────────────────────

function setAdminCsp(mode, flags) {
	sql(`UPDATE wp_csp_policy_profiles SET mode='${mode}', bypass_flags='${JSON.stringify(flags)}' WHERE surface='admin'`);
	sql("DELETE FROM wp_csp_violation_reports WHERE profile_surface='admin'");
	sql("DELETE FROM wp_options WHERE option_name LIKE '\\_transient%wp\\_sam\\_viol\\_%'");
}

async function uploadOnce(page, where, file) {
	const before = attachmentCount();
	const net = [];
	const onResp = (r) => {
		const u = r.url();
		if (/\/wp\/v2\/media|rest_route=%2Fwp%2Fv2%2Fmedia|async-upload\.php/.test(u)) {
			net.push(`${r.request().method()} ${u.replace(BASE, '').replace(/\?.*$/, '')} ${r.status()}`);
		}
	};
	page.on('response', onResp);
	const reports0 = reportPosts();
	const url = where === 'grid' ? `${BASE}/wp-admin/upload.php?mode=grid` : `${BASE}/wp-admin/media-new.php`;
	const resp = await page.goto(url, { waitUntil: 'load' });
	await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
	const headers = resp.headers();
	// Exact header lines: a page can carry more than one CSP header (WordPress
	// 7.1+ core adds its own "frame-ancestors 'self'"), and SAM's is the one
	// with default-src.
	const csp = (await resp.headersArray())
		.filter((h) => /^content-security-policy(-report-only)?$/i.test(h.name))
		.map((h) => ({ name: h.name.toLowerCase(), value: h.value }));
	const samCsp = csp.find((h) => /default-src/.test(h.value));
	const coi = await page.evaluate(() => window.crossOriginIsolated);
	const errors = [];
	const onError = (e) => errors.push(String(e.message).slice(0, 160));
	page.on('pageerror', onError);
	await page.waitForTimeout(2000);
	const shims = await page.locator('.moxie-shim input[type="file"]').count();
	const inputs = await page.locator('input[type="file"]').count();
	let uploaded = false;
	let uiBroken = '';
	if (shims + inputs === 0) {
		// The uploader never started -- e.g. the Media Library grid's
		// wp.template() needs 'unsafe-eval' (underscore's _.template).
		uiBroken = 'no file input: the uploader did not start';
	} else {
		const input = shims ? page.locator('.moxie-shim input[type="file"]').first() : page.locator('input[type="file"]').first();
		await input.setInputFiles(file);
		uploaded = await waitFor(() => attachmentCount() > before, 120000, 1500);
	}
	page.off('pageerror', onError);
	await page.waitForTimeout(4000);
	const uiErrors = await page.locator('.upload-error, .media-item .error-div, .upload-errors .upload-error').count();
	const pageViolations = await page.evaluate(() => window.__samCsp || []);
	await page.screenshot({ path: path.join(OUT, 'screenshots', `media_${where}_${Date.now()}.png`), fullPage: true });
	page.off('response', onResp);
	const pipeline = net.some((n) => /\/sideload|\/finalize/.test(n))
		? 'client-side (REST sideload/finalize)'
		: net.some((n) => /^POST \/wp-json\/wp\/v2\/media/.test(n))
			? 'REST /wp/v2/media (no sideload)'
			: net.some((n) => /async-upload\.php/.test(n))
				? 'server (async-upload.php)'
				: 'none observed';
	return {
		where,
		uploaded,
		ui_broken: uiBroken,
		page_errors: [...new Set(errors)],
		ui_errors: uiErrors,
		cross_origin_isolated: coi,
		document_isolation_policy: headers['document-isolation-policy'] || '',
		coop: headers['cross-origin-opener-policy'] || '',
		coep: headers['cross-origin-embedder-policy'] || '',
		sam_csp: samCsp ? (samCsp.name.endsWith('report-only') ? 'report-only' : 'enforce') : 'none',
		other_csp_headers: csp.filter((h) => h !== samCsp).map((h) => `${h.name}: ${h.value}`),
		worker_src: ((samCsp?.value || '').match(/worker-src[^;]*/) || [''])[0],
		script_src_keywords: ((samCsp?.value || '').match(/(?:^|; )script-src [^;]*/) || [''])[0].match(/'(?:wasm-unsafe-eval|unsafe-eval|strict-dynamic)'/g) || [],
		pipeline,
		requests: net,
		report_posts: reportPosts() - reports0,
		page_violations: pageViolations,
	};
}

async function media(file) {
	const ctx = await newContext();
	await login(ctx, ADMIN);
	const page = await ctx.newPage();
	const runs = [
		['report-only, defaults', 'report-only', []],
		['enforce, defaults', 'enforce', []],
		['enforce, worker_src_blob + script_src_wasm_unsafe_eval', 'enforce', ['worker_src_blob', 'script_src_wasm_unsafe_eval']],
		['enforce, worker_src_blob only', 'enforce', ['worker_src_blob']],
		['enforce, script_src_wasm_unsafe_eval only', 'enforce', ['script_src_wasm_unsafe_eval']],
	];
	// Direct report-uri delivery for this check: Chrome sends those at once,
	// where Reporting API (report-to) reports are batched for up to a minute.
	const transport = sql("SELECT option_value FROM wp_options WHERE option_name='wp_sam_reporting_transport'");
	sql("INSERT INTO wp_options (option_name, option_value, autoload) VALUES ('wp_sam_reporting_transport','report-uri','yes') ON DUPLICATE KEY UPDATE option_value='report-uri'");
	const out = [];
	for (const [label, mode, flags] of runs) {
		setAdminCsp(mode, flags);
		const uploads = [await uploadOnce(page, 'grid', file), await uploadOnce(page, 'media-new', file)];
		const violations = sqlRows("SELECT COALESCE(NULLIF(effective_directive,''),violated_directive), blocked_uri, occurrence_count FROM wp_csp_violation_reports WHERE profile_surface='admin' ORDER BY id").map(([d, b, n]) => `${d} ${b} x${n}`);
		out.push({ label, mode, flags, uploads, violations });
	}
	setAdminCsp('report-only', []);
	if (transport === '') sql("DELETE FROM wp_options WHERE option_name='wp_sam_reporting_transport'");
	else sql(`UPDATE wp_options SET option_value='${transport}' WHERE option_name='wp_sam_reporting_transport'`);
	result.media = out;
	await ctx.close();

	// A run only counts when the browser really received SAM's policy in the
	// mode under test -- otherwise it says nothing about that mode.
	const ok = (r) => r.uploads.every((u) => u.uploaded && u.ui_errors === 0 && u.sam_csp === r.mode);
	const [ro, enf, both, blobOnly, wasmOnly] = out;
	const desc = (r) =>
		`${r.label}: ${r.uploads
			.map((u) => `${u.where} ${u.uploaded ? 'ok' : `FAILED${u.ui_broken ? ` (${u.ui_broken}${u.page_errors.length ? '; ' + u.page_errors[0].slice(0, 90) : ''})` : ''}`}${u.ui_errors ? ` (${u.ui_errors} UI errors)` : ''} via ${u.pipeline}, SAM CSP ${u.sam_csp}${u.worker_src ? ` [${u.worker_src}${u.script_src_keywords.length ? '; script-src ' + u.script_src_keywords.join(' ') : ''}]` : ''}, COI ${u.cross_origin_isolated}, ${u.report_posts} reports sent, ${u.page_violations.length} violation events`)
			.join(' / ')}; SAM stored ${r.violations.length ? r.violations.join(', ') : 'nothing'}`;
	check('e1', ok(ro) ? 'pass' : 'fail', desc(ro));
	check('e2', ok(enf) ? 'pass' : 'fail', desc(enf));
	const clientUsed = both.uploads.some((u) => u.pipeline.startsWith('client-side'));
	check('e3', ok(both) && ok(blobOnly) && ok(wasmOnly) ? (clientUsed ? 'pass' : 'fail') : 'fail', `${desc(both)} | ${desc(blobOnly)} | ${desc(wasmOnly)}`);
}

// ── f) Traffic Guard: an editor's 30-image batch with the API enforcing ────

async function traffic(files, extraFiles = []) {
	sql("UPDATE wp_sam_traffic_policies SET mode='enforce' WHERE surface='api'");
	const limits = sqlRows("SELECT surface, mode, rate_limit_max_requests, rate_limit_window_seconds FROM wp_sam_traffic_policies ORDER BY surface");
	const ctx = await newContext();
	await login(ctx, EDITOR);
	const page = await ctx.newPage();
	const log = [];
	page.on('response', (r) => {
		const u = r.url();
		const kind = u.includes('/wp-json/') || u.includes('rest_route=') ? 'rest' : u.includes('async-upload.php') ? 'async-upload' : u.includes('admin-ajax.php') ? 'admin-ajax' : null;
		// responseStart is the wait for the first byte -- where Traffic Guard's
		// 1.5-second throttle would show.
		if (kind) log.push({ kind, status: r.status(), method: r.request().method(), url: u.replace(BASE, '').replace(/\?.*$/, ''), t: Date.now(), ttfb: Math.round(r.request().timing().responseStart) });
	});

	await page.goto(`${BASE}/wp-admin/post-new.php`, { waitUntil: 'load', timeout: 120000 });
	await page.waitForFunction(() => window.wp && wp.media && wp.data && wp.data.select('core/block-editor'), null, { timeout: 120000 });
	await page.evaluate(() => {
		try {
			wp.data.dispatch('core/preferences').set('core/edit-post', 'welcomeGuide', false);
		} catch (e) {}
	});
	await page.waitForLoadState('networkidle', { timeout: 20000 }).catch(() => {});

	const runs = [];

	// f1: the media modal (wp.media), as the task specifies.
	{
		const before = attachmentCount();
		const start = log.length;
		const t0 = Date.now();
		await page.evaluate(() => {
			window.__samFrame = wp.media({ title: 'Matrix batch', multiple: 'add', library: { type: 'image' } });
			window.__samFrame.open();
		});
		await page.waitForSelector('.media-modal', { state: 'visible' });
		const input = page.locator('.moxie-shim input[type="file"]').last();
		await input.setInputFiles(files);
		const done = await waitFor(() => attachmentCount() >= before + files.length, 600000, 3000);
		await page.waitForTimeout(3000);
		await page.screenshot({ path: path.join(OUT, 'screenshots', 'traffic_media-modal.png'), fullPage: true });
		await page.evaluate(() => window.__samFrame && window.__samFrame.close());
		runs.push(summariseBatch('media modal (wp.media)', log.slice(start), attachmentCount() - before, files.length, done, Date.now() - t0));
	}

	// Let the 60-second rate-limit window turn over between the two batches.
	await page.waitForTimeout(65000);

	// f2: the block editor's own upload path (what dropping files on a
	// Gallery block uses), which is where WordPress 7.2's client-side
	// processing sends every sub-size through the REST API.
	{
		const before = attachmentCount();
		const start = log.length;
		const t0 = Date.now();
		await page.evaluate(() => {
			const i = document.createElement('input');
			i.type = 'file';
			i.multiple = true;
			i.id = 'sam-matrix-files';
			document.body.appendChild(i);
		});
		await page.setInputFiles('#sam-matrix-files', files);
		await page.evaluate(() => {
			window.__samErrors = [];
			const upload = wp.data.select('core/block-editor').getSettings().mediaUpload;
			upload({
				filesList: Array.from(document.getElementById('sam-matrix-files').files),
				allowedTypes: ['image'],
				onFileChange: () => {},
				onError: (e) => window.__samErrors.push(String(e?.message || e)),
			});
		});
		const done = await waitFor(() => attachmentCount() >= before + files.length, 600000, 3000);
		await page.waitForTimeout(5000);
		const errors = await page.evaluate(() => window.__samErrors || []);
		const run = summariseBatch('block editor mediaUpload', log.slice(start), attachmentCount() - before, files.length, done, Date.now() - t0);
		run.upload_errors = errors.slice(0, 10);
		runs.push(run);
	}

	// SAM's rows for the client after the two 30-image batches -- check f.
	const blocksMain = sqlRows("SELECT surface, stage, reason, occurrence_count, COALESCE(blocked_until,'') FROM wp_sam_traffic_blocks WHERE ip LIKE '198.51.100.%'");

	// Informational, WordPress 7.2 only: a batch twice the size, to see where
	// the API surface's default limit starts to bite. Not part of check f.
	let extra = null;
	if (extraFiles.length) {
		await page.waitForTimeout(65000);
		const before = attachmentCount();
		const start = log.length;
		const t0 = Date.now();
		await page.setInputFiles('#sam-matrix-files', extraFiles);
		await page.evaluate(() => {
			window.__samErrors = [];
			wp.data.select('core/block-editor').getSettings().mediaUpload({
				filesList: Array.from(document.getElementById('sam-matrix-files').files),
				allowedTypes: ['image'],
				onFileChange: () => {},
				onError: (e) => window.__samErrors.push(String(e?.message || e)),
			});
		});
		const done = await waitFor(() => attachmentCount() >= before + extraFiles.length, 600000, 3000);
		await page.waitForTimeout(5000);
		extra = summariseBatch(`block editor mediaUpload, ${extraFiles.length} images (extra)`, log.slice(start), attachmentCount() - before, extraFiles.length, done, Date.now() - t0);
		extra.upload_errors = (await page.evaluate(() => window.__samErrors || [])).slice(0, 10);
		await page.screenshot({ path: path.join(OUT, 'screenshots', 'traffic_extra-batch.png'), fullPage: true });
	}

	const blocks = sqlRows("SELECT surface, stage, reason, occurrence_count, COALESCE(blocked_until,'') FROM wp_sam_traffic_blocks WHERE ip LIKE '198.51.100.%'");
	sql("UPDATE wp_sam_traffic_policies SET mode='observe' WHERE surface='api'");
	result.traffic = { limits, runs, sam_blocks_after_30_image_batches: blocksMain, extra, sam_blocks_after_extra: blocks };
	await ctx.close();

	// Any request over a surface's limit writes a sam_traffic_blocks row,
	// even at the 'warn' stage. Only the API surface is enforcing; an
	// 'admin' row (async-upload.php) says it WOULD have been limited.
	const limited = runs.some((r) => r.limited_responses > 0) || blocksMain.some((b) => b[0] === 'api');
	if (extra) {
		check(
			'f-extra',
			'info',
			`${extra.label}: ${extra.uploaded}/${extra.expected} uploaded in ${Math.round(extra.ms / 1000)}s, ${extra.rest_requests} REST requests (peak ${extra.rest_peak_per_60s}/60s), ${extra.limited_responses} limited (403/429/503), statuses ${JSON.stringify(extra.statuses)}; upload errors: ${extra.upload_errors.join(' | ') || 'none'}; SAM block rows for the client after all batches: ${blocks.length ? blocks.map((b) => b.join('/')).join(', ') : 'none'}`
		);
	}
	const complete = runs.every((r) => r.uploaded === r.expected);
	check(
		'f',
		limited || !complete ? 'fail' : 'pass',
		runs.map((r) => `${r.label}: ${r.uploaded}/${r.expected} uploaded in ${Math.round(r.ms / 1000)}s, ${r.rest_requests} REST requests (peak ${r.rest_peak_per_60s}/60s), ${r.async_upload_requests} async-upload.php, ${r.limited_responses} limited (403/429/503), slowest REST ${r.slowest_rest_ms}ms, ${r.rest_over_1400ms} REST over 1.4s (throttle)`).join(' | ') +
			`; SAM block rows for the client: ${blocksMain.length ? blocksMain.map((b) => b.join('/')).join(', ') : 'none'}`
	);
}

function summariseBatch(label, entries, uploaded, expected, done, ms) {
	const rest = entries.filter((e) => e.kind === 'rest');
	let peak = 0;
	for (let i = 0; i < rest.length; i++) {
		let j = i;
		while (j < rest.length && rest[j].t - rest[i].t < 60000) j++;
		peak = Math.max(peak, j - i);
	}
	const statuses = {};
	for (const e of entries) statuses[`${e.kind} ${e.status}`] = (statuses[`${e.kind} ${e.status}`] || 0) + 1;
	return {
		label,
		uploaded,
		expected,
		completed_in_time: done,
		ms,
		rest_requests: rest.length,
		rest_peak_per_60s: peak,
		async_upload_requests: entries.filter((e) => e.kind === 'async-upload').length,
		limited_responses: entries.filter((e) => [403, 429, 503].includes(e.status)).length,
		statuses,
		rest_routes: [...new Set(rest.map((e) => `${e.method} ${e.url.replace(/\/\d+/g, '/{id}')}`))],
		slowest_rest_ms: rest.reduce((m, e) => Math.max(m, e.ttfb || 0), 0),
		rest_over_1400ms: rest.filter((e) => (e.ttfb || 0) > 1400).length,
	};
}

// ── Fixtures: distinct JPEGs drawn in the browser ──────────────────────────

async function fixtures(count) {
	const dir = path.join(OUT, '..', '_fixtures');
	fs.mkdirSync(dir, { recursive: true });
	const page = await browser.newPage();
	const files = [];
	for (let i = 1; i <= count; i++) {
		const file = path.join(dir, `matrix-${String(i).padStart(2, '0')}.jpg`);
		if (!fs.existsSync(file)) {
			const data = await page.evaluate((n) => {
				const c = document.createElement('canvas');
				c.width = 1600;
				c.height = 1200;
				const g = c.getContext('2d');
				const grad = g.createLinearGradient(0, 0, 1600, 1200);
				grad.addColorStop(0, `hsl(${(n * 37) % 360},70%,45%)`);
				grad.addColorStop(1, `hsl(${(n * 71) % 360},60%,65%)`);
				g.fillStyle = grad;
				g.fillRect(0, 0, 1600, 1200);
				for (let k = 0; k < 400; k++) {
					g.fillStyle = `hsla(${(k * 13 + n * 7) % 360},80%,50%,0.35)`;
					g.beginPath();
					g.arc((k * 97 * n) % 1600, (k * 53 + n * 11) % 1200, 10 + ((k * n) % 60), 0, Math.PI * 2);
					g.fill();
				}
				g.fillStyle = '#fff';
				g.font = 'bold 160px sans-serif';
				g.fillText(`SAM ${n}`, 120, 640);
				return c.toDataURL('image/jpeg', 0.9).split(',')[1];
			}, i);
			fs.writeFileSync(file, Buffer.from(data, 'base64'));
		}
		files.push(file);
	}
	await page.close();
	return files;
}

// ── Run ────────────────────────────────────────────────────────────────────

const only = (opts.only || 'c,d,e,f').split(',');
try {
	const files = await fixtures(30);
	if (only.includes('c') || only.includes('d')) await pagesAndMenu();
	if (only.includes('e')) {
		if (IS_72) await media(files[0]);
		else check('e', 'not run', 'client-side media is WordPress 7.2 only');
	}
	if (only.includes('f')) await traffic(files, IS_72 ? (await fixtures(90)).slice(30) : []);
} catch (e) {
	check('browser', 'fail', `checks.mjs stopped: ${String(e.stack || e).slice(0, 600)}`);
	process.exitCode = 1;
} finally {
	await browser.close();
	fs.writeFileSync(path.join(OUT, 'browser.json'), JSON.stringify(result, null, 2));
	fs.appendFileSync(path.join(OUT, 'checks.tsv'), checks.map((c) => c.join('\t')).join('\n') + (checks.length ? '\n' : ''));
}
