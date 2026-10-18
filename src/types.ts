export interface Env {
	/** Comma-separated upstream DoH endpoints. Defaults to CF/Google/AliDNS. */
	UPSTREAM_DOH?: string;
	/** Comma- or space-separated domains to block (NXDOMAIN). */
	BLOCK_DOMAINS?: string;
	/** Remote adblock/hosts blocklist fetched every 6h. */
	BLOCKLIST_URL?: string;
	/** Upstream race timeout per attempt, ms. Default 5000. */
	UPSTREAM_TIMEOUT_MS?: string;
	/** How long the fastest upstream stays sticky, ms. Default 300000. */
	STICKY_TTL_MS?: string;
}
