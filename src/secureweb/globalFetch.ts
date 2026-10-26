import type ObsidianLiveSyncPlugin from "@/main";
import {
    createSecureWebFetch,
    registerConfiguredGatewayHosts,
    isRegisteredGatewayHost,
    transportLog,
    isGatewayInfrastructureRequest,
} from "./envelope";

export function installGlobalSecureWebFetch(getPlugin: () => ObsidianLiveSyncPlugin | undefined): () => void {
    if (typeof window === "undefined") return () => {};
    const win = window as any;
    win.__secureWebFetchInstalled = true;
    const origFetch = win.__secureWebRawFetch ?? win.fetch.bind(window);
    // Hand the pre-interception fetch to the transport: the sealed flow's
    // own control calls (session exchange) must bypass this interceptor,
    // or they recurse into the sealed flow again.
    win.__secureWebRawFetch = origFetch;

    const sealedFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (isGatewayInfrastructureRequest(input, init)) return origFetch(input, init);
        const plugin = getPlugin();
        const configuredUri = plugin?.core?.settings?.couchDB_URI || (plugin as any)?.settings?.couchDB_URI || "";
        registerConfiguredGatewayHosts(plugin?.core?.settings ?? (plugin as any)?.settings);
        if (isRegisteredGatewayHost(urlStr) && !urlStr.includes("/gateway/e2e-envelope")) {
            // Every gateway-bound request that is NOT the sealed envelope POST
            // is logged: these are the ones that can hit the blind-mode decoy.
            transportLog(`[fetch] ${String(init?.method ?? "GET").toUpperCase()} ${urlStr.split("?")[0].slice(0, 110)}`);
        }
        if (
            urlStr.includes("/gateway/e2e-envelope") ||
            urlStr.startsWith("secureweb:") ||
            isRegisteredGatewayHost(urlStr)
        ) {
            // Gateway infrastructure endpoints stay RAW: sealing them would
            // recurse (the sealed flow itself calls the session exchange and
            // the pubkey doc). They are plaintext routes by design.
            if (
                urlStr.includes("/gateway/service-session") ||
                urlStr.includes("/.well-known/") ||
                urlStr.includes("/transparency/") ||
                urlStr.includes("/healthz") ||
                urlStr.includes("/metrics")
            ) {
                return origFetch(input, init);
            }
            let gatewayUrl = urlStr.replace("secureweb:", "https:").replace(/\/gateway\/e2e-envelope\/?.*$/, "");
            try {
                gatewayUrl = new URL(gatewayUrl).origin;
            } catch {
                gatewayUrl = "https://localhost:8080";
            }
            // Service identity and path prefix come from configuration
            // (setup link / settings) — never hardcoded in the bundle.
            let basePath: string | undefined;
            try {
                const uriPath = configuredUri ? new URL(configuredUri.startsWith("http") ? configuredUri : `https://${configuredUri}`).pathname : "";
                if (uriPath && uriPath !== "/") {
                    basePath = uriPath.replace(/\/$/, "");
                }
            } catch {
                /* ignore malformed URI */
            }
            const serviceId =
                (plugin as any)?.core?.settings?.secureWebServiceId ||
                (plugin as any)?.settings?.secureWebServiceId;
            const passkeyToken =
                plugin?.core?.settings?.couchDB_PASSWORD ||
                (plugin as any)?.settings?.couchDB_PASSWORD ||
                undefined;
            const secureFetch = createSecureWebFetch({
                gatewayUrl: gatewayUrl || "https://localhost:8080",
                serviceId,
                targetHost: serviceId ? undefined : 'couchdb.local',
                basePath,
                passkeyToken,
            });
            return await secureFetch(input, init);
        }
        return origFetch(input, init);
    };
    win.fetch = sealedFetch;
    return () => {
        if (win.fetch === sealedFetch) {
            win.fetch = origFetch;
            win.__secureWebFetchInstalled = false;
        }
    };
}
