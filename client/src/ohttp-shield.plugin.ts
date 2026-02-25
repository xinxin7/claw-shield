import { BHttpDecoder, BHttpEncoder } from "bhttp-js";
import {
  Client,
  InvalidConfigIdError,
  InvalidContentTypeError,
  InvalidEncodingError,
} from "ohttp-js";
import { ClientConstructor } from "../node_modules/ohttp-js/esm/src/ohttp.js";
import * as fsPromises from "node:fs/promises";

const DEFAULT_ROUTE_PATH = "/api/plugins/ohttp/:provider/*";
const DEFAULT_GATEWAY_KEYS_URL =
  "https://claw-shield-gateway.ohttp.workers.dev/.well-known/ohttp-keys";
const DEFAULT_GATEWAY_URL = "https://claw-shield-gateway.ohttp.workers.dev/";
const DEFAULT_RELAY_URL = "https://claw-shield-relay.ohttp.workers.dev";
const DEFAULT_STATUS_PATH = "/api/plugins/claw-shield/status";
const DEFAULT_KEY_CACHE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_ALLOW_USER_SUPPLIED_CREDENTIALS = false;
const AUTH_STORE_CACHE_TTL_MS = 5 * 1000;

const DEFAULT_PROVIDER_TARGETS: Record<string, string> = {
  openai: "https://api.openai.com",
  google: "https://generativelanguage.googleapis.com",
  anthropic: "https://api.anthropic.com",
  openrouter: "https://openrouter.ai",
  mistral: "https://api.mistral.ai",
  groq: "https://api.groq.com",
};

const HOP_BY_HOP_HEADERS = new Set<string>([
  "connection",
  "proxy-connection",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "keep-alive",
  "trailer",
  "te",
]);

const PRIVACY_FILTERED_HEADERS = new Set<string>([
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
  "forwarded",
  "cf-connecting-ip",
  "cf-ray",
  "x-ohttp-target",
  "x-target-url",
]);

type UnknownRecord = Record<string, unknown>;
type AuthProfileLike = {
  type?: string;
  provider?: string;
  key?: string;
  token?: string;
  access?: string;
  apiKey?: string;
  accessToken?: string;
};

type ManagedAuthStore = {
  profiles: Record<string, AuthProfileLike>;
  lastGood: Record<string, string>;
};

type LoggerLike = {
  info?: (...args: unknown[]) => void;
  warn?: (...args: unknown[]) => void;
  error?: (...args: unknown[]) => void;
};

type RegisterHttpRouteOptions = {
  path: string;
  handler: (...args: unknown[]) => unknown;
};

export type ClawShieldPluginApi = {
  pluginConfig?: UnknownRecord;
  config?: UnknownRecord;
  logger?: LoggerLike;
  registerHttpHandler?: (
    handler: (req: NodeRequestLike, res: NodeResponseLike) => Promise<boolean> | boolean,
  ) => void;
  registerHttpRoute?: (options: RegisterHttpRouteOptions) => void;
};

export type ClawShieldPluginConfig = {
  routePath: string;
  gatewayKeysUrl: string;
  gatewayUrl: string;
  relayUrl: string;
  keyCacheTtlMs: number;
  allowUserSuppliedCredentials: boolean;
  providerTargets: Record<string, string>;
};

type NodeRequestLike = {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  [Symbol.asyncIterator]?: () => AsyncIterator<unknown>;
};

type NodeResponseLike = {
  statusCode?: number;
  setHeader?: (name: string, value: string) => void;
  writeHead?: (statusCode: number, headers?: Record<string, string>) => void;
  write?: (chunk: Uint8Array | Buffer | string) => boolean;
  end?: (chunk?: Uint8Array | Buffer | string) => void;
  flushHeaders?: () => void;
  flush?: () => void;
};

type KeyCacheEntry = {
  client: Client;
  expiresAt: number;
};

type NormalizedHttpInput = {
  request: Request;
  nodeResponse?: NodeResponseLike;
  routeParams?: Record<string, string | undefined>;
};

type RouteResolution = {
  provider: string;
  wildcardPath: string;
};

type InterceptedTarget = {
  provider: string;
  wildcardPath: string;
};

class HttpError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

class RelayResponseError extends Error {
  status: number;
  responseBody: string;

  constructor(status: number, responseBody: string) {
    super(`Relay returned status ${status}`);
    this.status = status;
    this.responseBody = responseBody;
  }
}

export class ClawShieldPlugin {
  private readonly api: ClawShieldPluginApi;
  private readonly logger: LoggerLike;
  private readonly config: ClawShieldPluginConfig;
  private keyCache: KeyCacheEntry | undefined;
  private keyInflight: Promise<Client> | undefined;
  private originalFetch: typeof fetch | undefined;
  private fetchInterceptionInstalled = false;
  private authStoreCache:
    | {
        store: ManagedAuthStore | null;
        expiresAt: number;
      }
    | undefined;

  constructor(api: ClawShieldPluginApi, cfg: Partial<ClawShieldPluginConfig> = {}) {
    this.api = api;
    this.logger = api?.logger ?? {};
    this.config = {
      routePath: cfg.routePath ?? DEFAULT_ROUTE_PATH,
      gatewayKeysUrl: cfg.gatewayKeysUrl ?? DEFAULT_GATEWAY_KEYS_URL,
      gatewayUrl: cfg.gatewayUrl ?? DEFAULT_GATEWAY_URL,
      relayUrl: cfg.relayUrl ?? DEFAULT_RELAY_URL,
      keyCacheTtlMs: cfg.keyCacheTtlMs ?? DEFAULT_KEY_CACHE_TTL_MS,
      allowUserSuppliedCredentials:
        cfg.allowUserSuppliedCredentials ?? DEFAULT_ALLOW_USER_SUPPLIED_CREDENTIALS,
      providerTargets: {
        ...DEFAULT_PROVIDER_TARGETS,
        ...(cfg.providerTargets ?? {}),
      },
    };
  }

  registerRoutes(): void {
    this.installGlobalFetchInterception();

    if (typeof this.api.registerHttpHandler !== "function") {
      throw new Error("Plugin API does not expose registerHttpHandler()");
    }

    this.api.registerHttpHandler(async (req, res) => {
      const method = (req.method ?? "GET").toUpperCase();
      const path = req.originalUrl ?? req.url ?? "/";
      const pathname = new URL(path, "http://localhost").pathname;
      if (method === "GET" && pathname === DEFAULT_STATUS_PATH) {
        const statusResponse = this.buildStatusResponse();
        await this.writeFetchResponseToNode(res, statusResponse);
        return true;
      }
      if (method !== "POST") {
        return false;
      }
      if (!this.shouldHandlePath(pathname)) {
        return false;
      }

      await this.handleHttpRequest(req, res);
      return true;
    });

    this.logInfo("claw-shield http handler registered", {
      methods: ["POST", "GET"],
      paths: [this.config.routePath, DEFAULT_STATUS_PATH],
    });
  }

  resolve_target_url(provider: string, wildcardPath: string, search = ""): string {
    const key = provider.toLowerCase();
    const base = this.config.providerTargets[key];
    if (!base) {
      throw new HttpError(400, `Unsupported provider: ${provider}`);
    }

    const normalizedBase = base.endsWith("/") ? base : `${base}/`;
    const normalizedPath = wildcardPath.startsWith("/")
      ? wildcardPath
      : `/${wildcardPath}`;
    const url = new URL(`${normalizedPath}${search}`, normalizedBase);
    return url.toString();
  }

  private installGlobalFetchInterception(): void {
    if (this.fetchInterceptionInstalled) {
      return;
    }

    const currentFetch = globalThis.fetch as (typeof fetch & {
      __clawShieldWrapped?: boolean;
      __clawShieldOriginal?: typeof fetch;
    });
    if (typeof currentFetch !== "function") {
      this.logWarn("global fetch is unavailable; internal provider interception disabled");
      return;
    }

    if (currentFetch.__clawShieldWrapped) {
      this.fetchInterceptionInstalled = true;
      this.originalFetch = currentFetch.__clawShieldOriginal ?? currentFetch;
      this.logInfo("global fetch interception already installed");
      return;
    }

    this.originalFetch = currentFetch.bind(globalThis) as typeof fetch;
    const wrappedFetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const originalFetchImpl = this.originalFetch;
      if (!originalFetchImpl) {
        throw new Error("Original fetch is unavailable");
      }

      const request = this.toFetchRequest(input, init);
      const method = request.method.toUpperCase();
      if (method !== "POST") {
        return originalFetchImpl(input, init);
      }

      const target = this.resolveInterceptedTarget(new URL(request.url));
      if (!target || !this.shouldHandlePath(target.wildcardPath)) {
        return originalFetchImpl(input, init);
      }

      this.logInfo("intercepting internal provider request via relay-gateway", {
        provider: target.provider,
        path: target.wildcardPath,
      });
      return await this.forwardWithRetry(request, target.provider, target.wildcardPath);
    }) as typeof fetch & {
      __clawShieldWrapped?: boolean;
      __clawShieldOriginal?: typeof fetch;
    };

    wrappedFetch.__clawShieldWrapped = true;
    wrappedFetch.__clawShieldOriginal = this.originalFetch;
    globalThis.fetch = wrappedFetch as typeof fetch;
    this.fetchInterceptionInstalled = true;
    this.logInfo("global fetch interception enabled for internal provider traffic");
  }

  private toFetchRequest(input: RequestInfo | URL, init?: RequestInit): Request {
    if (input instanceof Request) {
      return init ? new Request(input, init) : input.clone();
    }
    return new Request(input, init);
  }

  private resolveInterceptedTarget(targetUrl: URL): InterceptedTarget | undefined {
    for (const [provider, base] of Object.entries(this.config.providerTargets)) {
      let baseUrl: URL;
      try {
        baseUrl = new URL(base);
      } catch {
        continue;
      }

      if (targetUrl.origin !== baseUrl.origin) {
        continue;
      }

      const basePath = this.normalizeBasePath(baseUrl.pathname);
      if (!this.pathMatchesBase(targetUrl.pathname, basePath)) {
        continue;
      }

      const wildcardPath = this.trimBasePath(targetUrl.pathname, basePath);
      return {
        provider,
        wildcardPath,
      };
    }
    return undefined;
  }

  private normalizeBasePath(pathname: string): string {
    const normalized = pathname.trim().replace(/\/+$/, "");
    return normalized || "/";
  }

  private pathMatchesBase(pathname: string, basePath: string): boolean {
    if (basePath === "/") {
      return pathname.startsWith("/");
    }
    return pathname === basePath || pathname.startsWith(`${basePath}/`);
  }

  private trimBasePath(pathname: string, basePath: string): string {
    if (basePath === "/") {
      return pathname.startsWith("/") ? pathname : `/${pathname}`;
    }
    if (pathname === basePath) {
      return "/";
    }
    const trimmed = pathname.slice(basePath.length);
    return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  }

  private async handleHttpRequest(...args: unknown[]): Promise<Response | void> {
    try {
      const input = await this.normalizeInput(args);
      const route = await this.resolveRoute(input.request, input.routeParams);

      const upstreamResponse = await this.forwardWithRetry(
        input.request,
        route.provider,
        route.wildcardPath,
      );

      if (input.nodeResponse) {
        await this.writeFetchResponseToNode(input.nodeResponse, upstreamResponse);
        return;
      }

      return upstreamResponse;
    } catch (error) {
      const errResponse = this.toErrorResponse(error);
      const nodeResponse = this.maybeExtractNodeResponse(args);
      if (nodeResponse) {
        await this.writeFetchResponseToNode(nodeResponse, errResponse);
        return;
      }
      return errResponse;
    }
  }

  private async forwardWithRetry(
    incomingRequest: Request,
    provider: string,
    wildcardPath: string,
  ): Promise<Response> {
    try {
      return await this.forwardOnce(incomingRequest, provider, wildcardPath, false);
    } catch (error) {
      if (!this.shouldRefreshKey(error)) {
        throw error;
      }

      this.logWarn("key likely stale, refreshing gateway key config and retrying once");
      return await this.forwardOnce(incomingRequest, provider, wildcardPath, true);
    }
  }

  private async forwardOnce(
    incomingRequest: Request,
    provider: string,
    wildcardPath: string,
    forceRefreshKey: boolean,
  ): Promise<Response> {
    const providerKey = provider.toLowerCase();
    const targetUrl = new URL(incomingRequest.url);
    const headerApiKey =
      incomingRequest.headers.get("x-openai-api-key") ??
      incomingRequest.headers.get("x-api-key") ??
      incomingRequest.headers.get("openai-api-key");

    const outboundHeaders = this.buildOutboundHeaders(incomingRequest.headers);
    const managedCredential = await this.resolveManagedCredential(providerKey);
    this.logInfo("managed credential resolution completed", {
      provider: providerKey,
      hasManagedCredential: Boolean(managedCredential),
      allowUserSuppliedCredentials: this.config.allowUserSuppliedCredentials,
    });
    if (managedCredential) {
      this.applyManagedCredential(providerKey, targetUrl, outboundHeaders, managedCredential.token);
    } else if (this.config.allowUserSuppliedCredentials) {
      this.applyUserSuppliedCredential(providerKey, targetUrl, outboundHeaders, headerApiKey);
    }

    const resolvedTargetUrl = this.resolve_target_url(
      provider,
      wildcardPath,
      targetUrl.search,
    );
    if (!outboundHeaders.get("authorization")) {
      const names = Array.from(incomingRequest.headers.keys()).join(",");
      this.logWarn(`authorization missing after header normalization; inbound headers: ${names}`);
      throw new HttpError(
        401,
        `No managed credentials found for provider "${providerKey}". Configure it in OpenClaw auth profiles.`,
      );
    }

    const body = this.hasBody(incomingRequest.method)
      ? await this.normalizeRequestBodyForProvider(incomingRequest, providerKey)
      : undefined;

    const outboundRequest = new Request(resolvedTargetUrl, {
      method: incomingRequest.method,
      headers: outboundHeaders,
      body: body && body.byteLength > 0 ? this.toArrayBuffer(body) : undefined,
    });

    const encodedRequest = await new BHttpEncoder().encodeRequest(outboundRequest);
    const client = await this.getClient(forceRefreshKey);
    const requestContext = await client.encapsulate(encodedRequest);

    const baseRelayRequest = requestContext.request.request(this.config.relayUrl);
    const relayHeaders = new Headers(baseRelayRequest.headers);
    relayHeaders.set("x-ohttp-gateway-url", this.config.gatewayUrl);
    relayHeaders.set("accept", "message/ohttp-res");

    const relayFetchInit: RequestInit & { duplex?: "half" } = {
      method: "POST",
      headers: relayHeaders,
      body: baseRelayRequest.body,
      // Node's fetch requires duplex when request body is a stream.
      duplex: "half",
    };
    const relayResponse = await fetch(this.config.relayUrl, relayFetchInit);

    if (!relayResponse.ok) {
      const errorBody = await relayResponse.text().catch(() => "");
      throw new RelayResponseError(relayResponse.status, errorBody);
    }

    // NOTE: With RFC9458 single-shot encapsulation, full ciphertext is required
    // before decryption. True token-by-token decryption needs chunked OHTTP.
    const encryptedResponse = new Uint8Array(await relayResponse.arrayBuffer());
    const encodedResponse = await requestContext.decodeAndDecapsulate(encryptedResponse);
    const upstreamResponse = new BHttpDecoder().decodeResponse(encodedResponse);

    const contentType = upstreamResponse.headers.get("content-type") ?? "";
    if (contentType.toLowerCase().startsWith("text/event-stream")) {
      this.logInfo("SSE response detected, returning stream response to caller");
    }

    return upstreamResponse;
  }

  private normalizeApiToken(rawValue: string): string {
    const normalized = rawValue.trim();
    if (!normalized) {
      return normalized;
    }

    const parts = normalized
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
    const candidate = parts.length > 0 ? parts[parts.length - 1] : normalized;

    if (candidate.toLowerCase().startsWith("bearer ")) {
      return candidate.slice(7).trim();
    }

    return candidate;
  }

  private buildStatusResponse(): Response {
    const protectedMode = this.fetchInterceptionInstalled;
    const body = {
      ok: protectedMode,
      status: protectedMode ? "You're protected" : "Not protected",
      mode: "Gateway HTTP + internal provider interception",
      plugin: "claw-shield",
      relayUrl: this.config.relayUrl,
      gatewayUrl: this.config.gatewayUrl,
      gatewayKeysUrl: this.config.gatewayKeysUrl,
      allowUserSuppliedCredentials: this.config.allowUserSuppliedCredentials,
      timestamp: new Date().toISOString(),
    };
    return new Response(JSON.stringify(body), {
      status: protectedMode ? 200 : 503,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  private applyManagedCredential(
    providerKey: string,
    targetUrl: URL,
    outboundHeaders: Headers,
    token: string,
  ): void {
    switch (providerKey) {
      case "google":
        this.applyGoogleApiCredential(targetUrl, outboundHeaders, token);
        break;
      default:
        outboundHeaders.set("authorization", `Bearer ${token}`);
        break;
    }
  }

  private applyUserSuppliedCredential(
    providerKey: string,
    targetUrl: URL,
    outboundHeaders: Headers,
    headerApiKey: string | null,
  ): void {
    switch (providerKey) {
      case "google": {
        const queryApiKey =
          targetUrl.searchParams.get("key") ??
          targetUrl.searchParams.get("api_key") ??
          targetUrl.searchParams.get("openai_api_key") ??
          targetUrl.searchParams.get("token");
        const explicitApiKey = headerApiKey?.trim() || queryApiKey?.trim();
        if (explicitApiKey) {
          this.applyGoogleApiCredential(targetUrl, outboundHeaders, explicitApiKey);
        }
        break;
      }
      default: {
        const queryApiKey =
          targetUrl.searchParams.get("api_key") ??
          targetUrl.searchParams.get("openai_api_key") ??
          targetUrl.searchParams.get("token");
        const explicitApiKey = headerApiKey?.trim() || queryApiKey?.trim();
        if (explicitApiKey) {
          const normalizedToken = this.normalizeApiToken(explicitApiKey);
          outboundHeaders.set("authorization", `Bearer ${normalizedToken}`);
        }
        break;
      }
    }
  }

  private applyGoogleApiCredential(targetUrl: URL, outboundHeaders: Headers, token: string): void {
    targetUrl.searchParams.set("key", token);
    targetUrl.searchParams.delete("api_key");
    targetUrl.searchParams.delete("openai_api_key");
    targetUrl.searchParams.delete("token");
    outboundHeaders.set("authorization", `ApiKey ${token}`);
  }

  private async normalizeRequestBodyForProvider(
    incomingRequest: Request,
    provider: string,
  ): Promise<Uint8Array | undefined> {
    const rawBody = new Uint8Array(await incomingRequest.arrayBuffer());
    if (rawBody.byteLength === 0) {
      return undefined;
    }

    const contentType = incomingRequest.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json")) {
      return rawBody;
    }

    try {
      const text = new TextDecoder().decode(rawBody);
      const payload = JSON.parse(text) as UnknownRecord;
      if (!payload || typeof payload !== "object") {
        return rawBody;
      }

      const modelRaw = payload.model;
      if (typeof modelRaw !== "string" || !modelRaw.trim()) {
        return rawBody;
      }

      const parsed = this.parseModelRef(modelRaw, provider);
      if (!parsed || parsed.provider !== provider || parsed.model === modelRaw) {
        return rawBody;
      }

      const normalizedPayload = {
        ...payload,
        model: parsed.model,
      };
      return new TextEncoder().encode(JSON.stringify(normalizedPayload));
    } catch {
      return rawBody;
    }
  }

  private async resolveManagedCredential(provider: string): Promise<{ token: string } | null> {
    const store = await this.loadManagedAuthStore();
    if (!store) {
      return null;
    }

    const aliases = this.providerAliases(provider);
    let selectedProfileId: string | undefined;

    for (const alias of aliases) {
      const profileId = store.lastGood[alias];
      if (profileId && store.profiles[profileId]) {
        selectedProfileId = profileId;
        break;
      }
    }

    if (!selectedProfileId) {
      const configured = this.resolveConfiguredProfileId(provider);
      if (configured && store.profiles[configured]) {
        selectedProfileId = configured;
      }
    }

    if (!selectedProfileId) {
      for (const [profileId, profile] of Object.entries(store.profiles)) {
        if (this.providerMatches(provider, profile.provider)) {
          selectedProfileId = profileId;
          break;
        }
      }
    }

    if (!selectedProfileId) {
      return null;
    }

    const token = this.extractTokenFromProfile(store.profiles[selectedProfileId]);
    if (!token) {
      return null;
    }

    return { token };
  }

  private async loadManagedAuthStore(): Promise<ManagedAuthStore | null> {
    const now = Date.now();
    if (this.authStoreCache && this.authStoreCache.expiresAt > now) {
      return this.authStoreCache.store;
    }

    const stateDir = this.getEnvValue("OPENCLAW_STATE_DIR") || this.joinPath(this.getHomeDir(), ".openclaw");
    const explicitPath = this.getEnvValue("OPENCLAW_AUTH_PROFILES_PATH");
    const candidates = [
      explicitPath,
      this.joinPath(stateDir, "agents", "main", "agent", "auth-profiles.json"),
      this.joinPath(stateDir, "agents", "main", "agent", "auth.json"),
      this.joinPath(stateDir, "auth-profiles.json"),
      this.joinPath(stateDir, "auth.json"),
    ].filter((value): value is string => Boolean(value && value.trim()));
    this.logInfo(`managed auth store candidates: ${candidates.join(" | ")}`);

    for (const candidate of candidates) {
      try {
        const raw = await this.readFileUtf8(candidate);
        const parsed = JSON.parse(raw) as UnknownRecord;
        const normalized = this.normalizeAuthStore(parsed);
        if (normalized) {
          this.logInfo(
            `loaded managed auth store from ${candidate} (profiles=${Object.keys(normalized.profiles).length},lastGood=${Object.keys(normalized.lastGood).join(",")})`,
          );
          this.authStoreCache = {
            store: normalized,
            expiresAt: now + AUTH_STORE_CACHE_TTL_MS,
          };
          return normalized;
        }
      } catch (error) {
        this.logWarn(`failed auth store candidate ${candidate}: ${this.errorText(error)}`);
        continue;
      }
    }

    this.logWarn("managed auth store not found in any candidate path");
    this.authStoreCache = {
      store: null,
      expiresAt: now + AUTH_STORE_CACHE_TTL_MS,
    };
    return null;
  }

  private getHomeDir(): string {
    return this.getEnvValue("HOME") || this.getEnvValue("USERPROFILE") || "";
  }

  private getEnvValue(name: string): string {
    const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
    const value = env?.[name];
    return typeof value === "string" ? value.trim() : "";
  }

  private joinPath(base: string, ...parts: string[]): string {
    const sep = base.includes("\\") ? "\\" : "/";
    const normalizedBase = base.replace(/[\\/]+$/, "");
    const normalizedParts = parts.map((part) => part.replace(/^[\\/]+|[\\/]+$/g, ""));
    return [normalizedBase, ...normalizedParts].filter(Boolean).join(sep);
  }

  private async readFileUtf8(filePath: string): Promise<string> {
    return await fsPromises.readFile(filePath, "utf8");
  }

  private normalizeAuthStore(raw: UnknownRecord): ManagedAuthStore | null {
    const maybeProfiles = raw.profiles;
    if (maybeProfiles && typeof maybeProfiles === "object") {
      const profiles: Record<string, AuthProfileLike> = {};
      for (const [id, profile] of Object.entries(maybeProfiles as UnknownRecord)) {
        if (profile && typeof profile === "object") {
          profiles[id] = profile as AuthProfileLike;
        }
      }
      const lastGoodRaw = raw.lastGood;
      const lastGood: Record<string, string> = {};
      if (lastGoodRaw && typeof lastGoodRaw === "object") {
        for (const [provider, profileId] of Object.entries(lastGoodRaw as UnknownRecord)) {
          if (typeof profileId === "string") {
            lastGood[provider.toLowerCase()] = profileId;
          }
        }
      }
      return {
        profiles,
        lastGood,
      };
    }

    // Legacy shape: { "<provider>": { type, key/... } }
    const profiles: Record<string, AuthProfileLike> = {};
    for (const [provider, profile] of Object.entries(raw)) {
      if (!profile || typeof profile !== "object") {
        continue;
      }
      profiles[`${provider}:legacy`] = {
        ...(profile as AuthProfileLike),
        provider,
      };
    }
    if (Object.keys(profiles).length === 0) {
      return null;
    }
    return {
      profiles,
      lastGood: {},
    };
  }

  private resolveConfiguredProfileId(provider: string): string | undefined {
    const root = this.api.config;
    if (!root || typeof root !== "object") {
      return undefined;
    }
    const profiles = ((root as UnknownRecord).auth as UnknownRecord | undefined)?.profiles;
    if (!profiles || typeof profiles !== "object") {
      return undefined;
    }

    for (const [id, profile] of Object.entries(profiles as UnknownRecord)) {
      if (!profile || typeof profile !== "object") {
        continue;
      }
      const p = (profile as UnknownRecord).provider;
      if (typeof p === "string" && this.providerMatches(provider, p)) {
        return id;
      }
    }
    return undefined;
  }

  private providerAliases(provider: string): string[] {
    const normalized = provider.toLowerCase();
    if (normalized === "openai") {
      return ["openai", "openai-codex"];
    }
    if (normalized === "google") {
      return ["google", "gemini"];
    }
    return [normalized];
  }

  private providerMatches(expected: string, actual?: string): boolean {
    if (!actual) {
      return false;
    }
    const normalizedActual = actual.toLowerCase();
    return this.providerAliases(expected).includes(normalizedActual);
  }

  private extractTokenFromProfile(profile?: AuthProfileLike): string | undefined {
    if (!profile) {
      return undefined;
    }

    const type = profile.type?.toLowerCase();
    if (type === "oauth") {
      return profile.access?.trim() || profile.accessToken?.trim();
    }
    if (type === "token") {
      return profile.token?.trim() || profile.key?.trim();
    }

    // api_key and unknown types both use key/token style fields.
    return (
      profile.key?.trim() ||
      profile.apiKey?.trim() ||
      profile.token?.trim() ||
      profile.access?.trim() ||
      profile.accessToken?.trim()
    );
  }

  private async getClient(forceRefresh = false): Promise<Client> {
    const now = Date.now();
    if (!forceRefresh && this.keyCache && this.keyCache.expiresAt > now) {
      return this.keyCache.client;
    }

    if (!forceRefresh && this.keyInflight) {
      return this.keyInflight;
    }

    const inflight = this.fetchAndBuildClient();
    this.keyInflight = inflight;
    try {
      const client = await inflight;
      this.keyCache = {
        client,
        expiresAt: Date.now() + this.config.keyCacheTtlMs,
      };
      return client;
    } finally {
      this.keyInflight = undefined;
    }
  }

  private async fetchAndBuildClient(): Promise<Client> {
    const response = await fetch(this.config.gatewayKeysUrl, {
      method: "GET",
      headers: {
        accept: "application/ohttp-keys",
      },
    });

    if (!response.ok) {
      throw new Error(
        `Failed to fetch gateway key config: ${response.status} ${response.statusText}`,
      );
    }

    const keyConfigList = new Uint8Array(await response.arrayBuffer());
    const firstConfig = this.pickFirstKeyConfig(keyConfigList);
    this.logInfo("fetched OHTTP key config list", {
      listBytes: keyConfigList.byteLength,
      firstConfigBytes: firstConfig.byteLength,
    });

    const constructor = new ClientConstructor();
    return await constructor.clientForConfig(firstConfig);
  }

  private pickFirstKeyConfig(encodedList: Uint8Array): Uint8Array {
    if (encodedList.byteLength < 4) {
      throw new Error("Gateway key config list is too short");
    }

    const len = (encodedList[0] << 8) | encodedList[1];
    const end = 2 + len;
    if (len <= 0 || end > encodedList.byteLength) {
      throw new Error("Gateway key config list has invalid first entry length");
    }

    return encodedList.slice(2, end);
  }

  private buildOutboundHeaders(incomingHeaders: Headers): Headers {
    const headers = new Headers();
    for (const [rawName, value] of incomingHeaders.entries()) {
      const name = rawName.toLowerCase();
      if (name === "x-openai-api-key" || name === "x-api-key" || name === "openai-api-key") {
        // Use these only for local auth normalization; do not forward upstream.
        continue;
      }
      if (HOP_BY_HOP_HEADERS.has(name) || PRIVACY_FILTERED_HEADERS.has(name)) {
        continue;
      }
      headers.append(name, value);
    }

    return headers;
  }

  private async resolveRoute(
    request: Request,
    params?: Record<string, string | undefined>,
  ): Promise<RouteResolution> {
    const fallback = await this.resolveRouteFromPathname(new URL(request.url).pathname, request);
    if (!params) {
      return fallback;
    }

    const provider = params.provider ?? fallback.provider;
    const wildcard = params["*"] ?? params.wildcard ?? params["0"] ?? fallback.wildcardPath;
    return {
      provider,
      wildcardPath: wildcard.startsWith("/") ? wildcard : `/${wildcard}`,
    };
  }

  private async resolveRouteFromPathname(pathname: string, request: Request): Promise<RouteResolution> {
    const m = pathname.match(/^\/api\/plugins\/ohttp\/([^/]+)\/?(.*)$/i);
    if (m) {
      const provider = decodeURIComponent(m[1]);
      const tail = m[2] ?? "";
      return {
        provider,
        wildcardPath: tail ? `/${tail}` : "/",
      };
    }

    if (this.isOpenAiCompatiblePath(pathname)) {
      const defaultRef = this.resolveDefaultModelRefFromConfig();
      const modelRefRaw = await this.extractModelRefFromRequest(request);
      const parsed = modelRefRaw
        ? this.parseModelRef(modelRefRaw, defaultRef?.provider ?? "openai")
        : defaultRef;
      const inferredProvider = parsed?.provider ?? "openai";
      const provider = this.isOpenAiCompatibleProvider(inferredProvider)
        ? inferredProvider
        : this.isOpenAiCompatibleProvider(defaultRef?.provider ?? "")
          ? (defaultRef?.provider ?? "openai")
          : "openai";
      return {
        provider,
        wildcardPath: pathname,
      };
    }

    if (this.isAnthropicPath(pathname)) {
      return {
        provider: "anthropic",
        wildcardPath: pathname,
      };
    }

    if (this.isGooglePath(pathname)) {
      return {
        provider: "google",
        wildcardPath: pathname,
      };
    }

    throw new HttpError(404, `Route not matched: ${pathname}`);
  }

  private shouldHandlePath(pathname: string): boolean {
    return (
      /^\/api\/plugins\/ohttp\/[^/]+\/?.*$/i.test(pathname) ||
      this.isOpenAiCompatiblePath(pathname) ||
      this.isAnthropicPath(pathname) ||
      this.isGooglePath(pathname)
    );
  }

  private isOpenAiCompatiblePath(pathname: string): boolean {
    return /^\/v1\/(?:chat\/completions|responses|completions|embeddings)$/i.test(pathname);
  }

  private isOpenAiCompatibleProvider(provider: string): boolean {
    return ["openai", "openrouter", "groq", "mistral"].includes(provider.toLowerCase());
  }

  private isAnthropicPath(pathname: string): boolean {
    return /^\/v1\/messages$/i.test(pathname);
  }

  private isGooglePath(pathname: string): boolean {
    return /^\/v1(?:beta)?\/models\/[^/]+:(?:generatecontent|streamgeneratecontent|counttokens|embedcontent)$/i.test(
      pathname,
    );
  }

  private async extractModelRefFromRequest(request: Request): Promise<string | undefined> {
    const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json")) {
      return undefined;
    }

    try {
      const body = (await request.clone().json()) as UnknownRecord;
      const model = body?.model;
      return typeof model === "string" && model.trim() ? model.trim() : undefined;
    } catch {
      return undefined;
    }
  }

  private parseModelRef(
    raw: string,
    defaultProvider = "openai",
  ): { provider: string; model: string } | undefined {
    const normalized = raw.trim();
    if (!normalized) {
      return undefined;
    }

    const splitAt = normalized.indexOf("/");
    if (splitAt <= 0 || splitAt >= normalized.length - 1) {
      return {
        provider: defaultProvider.toLowerCase(),
        model: normalized,
      };
    }

    return {
      provider: normalized.slice(0, splitAt).toLowerCase(),
      model: normalized.slice(splitAt + 1),
    };
  }

  private resolveDefaultModelRefFromConfig():
    | {
        provider: string;
        model: string;
      }
    | undefined {
    const root = this.api.config;
    if (!root || typeof root !== "object") {
      return undefined;
    }
    const cfg = root as UnknownRecord;
    const primary = (((cfg.agents as UnknownRecord | undefined)?.defaults as UnknownRecord | undefined)?.model as
      | UnknownRecord
      | undefined)?.primary;
    if (typeof primary !== "string" || !primary.trim()) {
      return undefined;
    }
    return this.parseModelRef(primary.trim(), "openai");
  }

  private async normalizeInput(args: unknown[]): Promise<NormalizedHttpInput> {
    const [first, second] = args;

    if (first instanceof Request) {
      const routeParams = this.readRouteParams(second);
      return {
        request: first,
        routeParams,
      };
    }

    if (this.looksLikeNodeRequest(first)) {
      const nodeRequest = first as NodeRequestLike;
      const nodeResponse = this.looksLikeNodeResponse(second) ? (second as NodeResponseLike) : undefined;
      const request = await this.nodeRequestToFetchRequest(nodeRequest);
      return {
        request,
        nodeResponse,
      };
    }

    // Some runtimes pass a context object with req/res.
    if (this.looksLikeRequestContext(first)) {
      const ctx = first as { req?: NodeRequestLike; res?: NodeResponseLike; params?: UnknownRecord };
      if (!ctx.req) {
        throw new Error("Invalid HTTP context: missing req");
      }
      const request = await this.nodeRequestToFetchRequest(ctx.req);
      return {
        request,
        nodeResponse: ctx.res,
        routeParams: this.readRouteParams(ctx),
      };
    }

    throw new Error("Unsupported route handler signature");
  }

  private readRouteParams(source: unknown): Record<string, string | undefined> | undefined {
    if (!source || typeof source !== "object") {
      return undefined;
    }
    const maybeParams = (source as UnknownRecord).params;
    if (!maybeParams || typeof maybeParams !== "object") {
      return undefined;
    }

    const out: Record<string, string | undefined> = {};
    for (const [k, v] of Object.entries(maybeParams as UnknownRecord)) {
      if (typeof v === "string") {
        out[k] = v;
      }
    }
    return out;
  }

  private async nodeRequestToFetchRequest(nodeReq: NodeRequestLike): Promise<Request> {
    const method = (nodeReq.method ?? "GET").toUpperCase();
    const headers = new Headers();
    for (const [key, val] of Object.entries(nodeReq.headers ?? {})) {
      if (val === undefined) {
        continue;
      }
      if (Array.isArray(val)) {
        for (const item of val) {
          headers.append(key, item);
        }
      } else {
        headers.set(key, val);
      }
    }

    const host = headers.get("host") ?? "localhost";
    const proto = headers.get("x-forwarded-proto") ?? "http";
    const path = nodeReq.originalUrl ?? nodeReq.url ?? "/";
    const url = new URL(path, `${proto}://${host}`).toString();

    const body = this.hasBody(method) ? await this.readNodeBody(nodeReq) : undefined;
    return new Request(url, {
      method,
      headers,
      body: body && body.byteLength > 0 ? this.toArrayBuffer(body) : undefined,
    });
  }

  private toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  }

  private async readNodeBody(nodeReq: NodeRequestLike): Promise<Uint8Array> {
    if (nodeReq.body instanceof Uint8Array) {
      return nodeReq.body;
    }
    if (typeof nodeReq.body === "string") {
      return new TextEncoder().encode(nodeReq.body);
    }
    if (nodeReq.body instanceof ArrayBuffer) {
      return new Uint8Array(nodeReq.body);
    }

    if (typeof nodeReq[Symbol.asyncIterator] === "function") {
      const chunks: Uint8Array[] = [];
      // eslint-disable-next-line no-restricted-syntax
      for await (const chunk of nodeReq as AsyncIterable<unknown>) {
        if (chunk instanceof Uint8Array) {
          chunks.push(chunk);
        } else if (chunk instanceof ArrayBuffer) {
          chunks.push(new Uint8Array(chunk));
        } else if (typeof chunk === "string") {
          chunks.push(new TextEncoder().encode(chunk));
        } else if (chunk && typeof Buffer !== "undefined" && Buffer.isBuffer(chunk)) {
          chunks.push(new Uint8Array(chunk));
        }
      }

      if (chunks.length === 0) {
        return new Uint8Array();
      }

      const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
      const out = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return out;
    }

    return new Uint8Array();
  }

  private async writeFetchResponseToNode(
    nodeRes: NodeResponseLike,
    response: Response,
  ): Promise<void> {
    const headerObj: Record<string, string> = {};
    for (const [key, value] of response.headers.entries()) {
      headerObj[key] = value;
    }

    if (typeof nodeRes.writeHead === "function") {
      nodeRes.writeHead(response.status, headerObj);
    } else {
      nodeRes.statusCode = response.status;
      if (typeof nodeRes.setHeader === "function") {
        for (const [key, value] of Object.entries(headerObj)) {
          nodeRes.setHeader(key, value);
        }
      }
    }

    if (typeof nodeRes.flushHeaders === "function") {
      nodeRes.flushHeaders();
    }

    if (!response.body) {
      nodeRes.end?.();
      return;
    }

    const reader = response.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value && value.byteLength > 0) {
        nodeRes.write?.(Buffer.from(value));
        nodeRes.flush?.();
      }
    }
    nodeRes.end?.();
  }

  private shouldRefreshKey(error: unknown): boolean {
    if (error instanceof InvalidConfigIdError) {
      return true;
    }
    if (error instanceof InvalidEncodingError) {
      return true;
    }
    if (error instanceof InvalidContentTypeError) {
      return true;
    }
    if (error instanceof RelayResponseError) {
      return error.status === 400 || error.status === 401;
    }

    const text = this.errorText(error).toLowerCase();
    return (
      text.includes("invalid configuration id") ||
      text.includes("invalid content type") ||
      text.includes("invalid message encoding")
    );
  }

  private hasBody(method: string): boolean {
    const normalized = method.toUpperCase();
    return !["GET", "HEAD"].includes(normalized);
  }

  private toErrorResponse(error: unknown): Response {
    if (error instanceof HttpError) {
      return new Response(error.message, { status: error.status });
    }

    if (error instanceof RelayResponseError) {
      const body = error.responseBody || "relay error";
      return new Response(body, { status: 502 });
    }

    this.logError("claw shield plugin request failed", error);
    return new Response("Internal Server Error", { status: 500 });
  }

  private maybeExtractNodeResponse(args: unknown[]): NodeResponseLike | undefined {
    const [, second] = args;
    if (this.looksLikeNodeResponse(second)) {
      return second as NodeResponseLike;
    }
    const [first] = args;
    if (first && typeof first === "object" && this.looksLikeNodeResponse((first as UnknownRecord).res)) {
      return (first as { res: NodeResponseLike }).res;
    }
    return undefined;
  }

  private looksLikeNodeRequest(value: unknown): boolean {
    if (!value || typeof value !== "object") {
      return false;
    }
    const v = value as UnknownRecord;
    return typeof v.method === "string" && typeof (v.url ?? v.originalUrl) === "string";
  }

  private looksLikeNodeResponse(value: unknown): boolean {
    if (!value || typeof value !== "object") {
      return false;
    }
    const v = value as UnknownRecord;
    return (
      typeof v.writeHead === "function" ||
      typeof v.setHeader === "function" ||
      typeof v.end === "function"
    );
  }

  private looksLikeRequestContext(value: unknown): boolean {
    if (!value || typeof value !== "object") {
      return false;
    }
    const v = value as UnknownRecord;
    return "req" in v || "res" in v;
  }

  private errorText(error: unknown): string {
    if (error instanceof Error) {
      return `${error.name}: ${error.message}`;
    }
    return String(error);
  }

  private logInfo(message: string, extra?: UnknownRecord): void {
    this.logger.info?.(`[claw-shield] ${message}`, extra ?? {});
  }

  private logWarn(message: string, extra?: UnknownRecord): void {
    this.logger.warn?.(`[claw-shield] ${message}`, extra ?? {});
  }

  private logError(message: string, error: unknown): void {
    this.logger.error?.(`[claw-shield] ${message}: ${this.errorText(error)}`);
  }
}
