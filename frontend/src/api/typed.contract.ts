import { post, request } from "./typed";

/** Compile-only regression checks; never invoked or included in the application bundle. */
export function verifyRequestContracts() {
  request("patch", "/api/v1/findings/{finding_id}", { params: { finding_id: 1 }, body: { status: "resolved" } });
  request("get", "/api/v1/findings", { query: { severity: ["high"] } }).then((result) => result.total);
  request("post", "/api/v1/findings/bulk", { body: { ids: [1], status: "resolved" } }).then((result) => result.updated);
  // @ts-expect-error PATCH cannot target a GET-only endpoint.
  request("patch", "/api/v1/analytics/summary", { body: {} });
  // @ts-expect-error Path parameters are required.
  request("patch", "/api/v1/findings/{finding_id}", { body: {} });
  // @ts-expect-error Unknown statuses must not reach the API.
  request("patch", "/api/v1/findings/{finding_id}", { params: { finding_id: 1 }, body: { status: "done" } });
  // @ts-expect-error Unknown query fields must not silently disappear.
  request("get", "/api/v1/findings", { query: { unsupported: true } });
  request("post", "/api/v1/scans", { form: { file: new Blob(["{}"]), asset_id: 1, preview: true } });
  // @ts-expect-error Multipart requests must include the uploaded file.
  request("post", "/api/v1/scans", { form: { asset_id: 1 } });
  // @ts-expect-error Upload fields retain their backend types.
  request("post", "/api/v1/scans", { form: { file: new Blob(), asset_id: "bad" } });
  // @ts-expect-error A numeric filter cannot accidentally receive a URL string.
  request("get", "/api/v1/analytics/summary", { query: { asset_id: "1" } });
  // @ts-expect-error Endpoints with required query parameters cannot omit the query.
  request("get", "/api/v1/search", {});
  // @ts-expect-error The simple POST helper cannot omit required path parameters.
  post("/api/v1/findings/{finding_id}/comments", { text: "comment" });
}
