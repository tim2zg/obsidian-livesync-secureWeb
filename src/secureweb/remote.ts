import { InjectableRemoteService } from "@vrtmrz/livesync-commonlib/compat/services/implements/injectable/InjectableRemoteService";
import type { ServiceContext } from "@vrtmrz/livesync-commonlib/context";
import { createDeviceId, createSecureWebFetch, SecureWebEnvelopeError } from "@/secureweb/envelope";

const ENVELOPE_PATH = "/gateway/e2e-envelope";

/** Keep the encrypted transport at the shared CouchDB HTTP boundary. */
export class SecureWebRemoteService<T extends ServiceContext> extends InjectableRemoteService<T> {
    private readonly deviceId = createDeviceId();

    override async connect(...args: Parameters<InjectableRemoteService<T>["connect"]>) {
        if (args[0].startsWith("secureweb:")) {
            const url = new URL(args[0].replace(/^secureweb:/, "https:"));
            if (url.pathname !== ENVELOPE_PATH && !url.pathname.startsWith(`${ENVELOPE_PATH}/`)) {
                url.pathname = ENVELOPE_PATH + url.pathname;
            }
            args[0] = url.toString();
        }
        return await super.connect(...args);
    }

    override async performFetch(
        req: string | Request,
        opts?: RequestInit,
        fetchMethod?: Parameters<InjectableRemoteService<T>["performFetch"]>[2]
    ): Promise<Response> {
        const url = new URL(typeof req === "string" ? req : req.url);
        if (url.pathname !== ENVELOPE_PATH && !url.pathname.startsWith(`${ENVELOPE_PATH}/`)) {
            return await super.performFetch(req, opts, fetchMethod);
        }

        const headers = new Headers(req instanceof Request ? req.headers : undefined);
        new Headers(opts?.headers).forEach((value, key) => headers.set(key, value));
        const authorization = headers.get("authorization");
        if (authorization?.toLowerCase().startsWith("basic ")) {
            // PouchDB supplies the credentials captured by this connection,
            // including a setup probe for a profile which is not yet active.
            let credentials: string;
            try {
                credentials = atob(authorization.slice(6));
            } catch {
                throw new SecureWebEnvelopeError("Invalid connection credentials");
            }
            const separator = credentials.indexOf(":");
            if (separator < 0) throw new SecureWebEnvelopeError("Invalid connection credentials");
            headers.set("authorization", `Bearer ${credentials.slice(separator + 1)}`);
        }

        const secureFetch = createSecureWebFetch({
            gatewayUrl: url.origin,
            targetHost: "couchdb.local",
            deviceId: this.deviceId,
            networkFetch: (input, init) => {
                const request = input instanceof URL ? input.toString() : input;
                return super.performFetch(request, init, fetchMethod);
            },
        });
        const response = await secureFetch(url, {
            ...opts,
            method: opts?.method ?? (req instanceof Request ? req.method : "GET"),
            headers,
            body: opts?.body !== undefined ? opts.body : req instanceof Request ? await req.clone().arrayBuffer() : undefined,
            signal: opts?.signal ?? (req instanceof Request ? req.signal : undefined),
        });
        const method = opts?.method ?? (req instanceof Request ? req.method : "GET");
        this.last_successful_post = method === "POST" || method === "PUT" ? response.ok : true;
        return response;
    }
}
