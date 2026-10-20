export interface Env {
	/** Comma-separated upstream DoH endpoints. Defaults to CF/Google/AliDNS. */
	UPSTREAM_DOH?: string;
	/**
	 * Region overrides, "CODE=url[,url];CODE=url…" — CODE is an ISO country
	 * (JP) or continent (AS/EU/…) two-letter code. Match order: per-request
	 * up= > country > continent > UPSTREAM_DOH.
	 */
	UPSTREAM_REGIONS?: string;
	/** Comma- or space-separated domains to block (NXDOMAIN). */
	BLOCK_DOMAINS?: string;
	/** Comma- or space-separated exception domains (never filtered). */
	ALLOW_DOMAINS?: string;
	/** Remote filter lists (adblock/hosts/dnsmasq), comma-separated, every 6h. */
	BLOCKLIST_URL?: string;
	/** Default block reply mode: nxdomain (default), refused, noaddr or an IP. */
	BLOCK_MODE?: string;
	/** Upstream race timeout per attempt, ms. Default 5000. */
	UPSTREAM_TIMEOUT_MS?: string;
	/** How long the fastest upstream stays sticky, ms. Default 300000. */
	STICKY_TTL_MS?: string;
}
