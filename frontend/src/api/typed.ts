import { api, download as downloadFile } from "./client";
import type { paths } from "./schema";

type Method = "get" | "post" | "patch" | "put" | "delete";
type PathFor<M extends Method> = {
  [P in keyof paths]: paths[P] extends Record<M, object> ? P : never;
}[keyof paths];
type Operation<P extends keyof paths, M extends Method> = paths[P][M &
  keyof paths[P]];
type MediaBody<T, Media extends string> = T extends { requestBody: { content: infer C } }
  ? Media extends keyof C ? C[Media] : never : never;
type JsonBody<T> = MediaBody<T, "application/json">;
type FormBody<T> = MediaBody<T, "multipart/form-data">;
export type RequestBody<P extends PathFor<M>, M extends Method = "post"> = JsonBody<Operation<P, M>>;
export type Query<P extends PathFor<"get">> = Params<Operation<P, "get">, "query">;
type Params<T, K extends string> = T extends { parameters: infer P }
  ? K extends keyof P
    ? NonNullable<P[K]>
    : never
  : never;
type JsonResponse<T> = T extends { responses: infer R }
  ? {
      [K in keyof R]: K extends "200" | "201" | "202" | "204" | 200 | 201 | 202 | 204
        ? R[K] extends { content: { "application/json": infer B } }
          ? B
          : undefined
        : never;
    }[keyof R]
  : never;
type QueryOptions<T> = Params<T, "query"> extends never ? { query?: never }
  : Record<string, never> extends Params<T, "query"> ? { query?: Params<T, "query"> } : { query: Params<T, "query"> };
type Options<T> = (Params<T, "path"> extends never ? { params?: never } : { params: Params<T, "path"> })
  & QueryOptions<T> & { signal?: AbortSignal }
  & (JsonBody<T> extends never
    ? FormBody<T> extends never ? { body?: never; form?: never } : { body?: never; form: FormBody<T> }
    : { body: JsonBody<T>; form?: never });
type SimplePostPath = { [P in PathFor<"post">]: Params<Operation<P, "post">, "path"> extends never ? P : never }[PathFor<"post">];

/** The generated schema checks the method, path parameters, filters, body and success response. */
export function request<M extends Method, P extends PathFor<M>>(
  method: M,
  path: P,
  options: Options<Operation<P, M>>,
) {
  const params = options.params as Record<string, string | number> | undefined;
  const resolved = path.replace(/\{([^}]+)\}/g, (_, key: string) =>
    encodeURIComponent(String(params?.[key])),
  );
  return api<JsonResponse<Operation<P, M>>>(resolved.slice("/api/v1".length), {
    method: method.toUpperCase(),
    body: options.body,
    form: options.form ? encodeForm(options.form) : undefined,
    query: options.query,
    signal: options.signal,
  });
}

/** Convenience for existing authentication callers. */
export function post<P extends SimplePostPath>(
  path: P,
  body: JsonBody<Operation<P, "post">>,
) {
  return api<JsonResponse<Operation<P, "post">>>(path.slice("/api/v1".length), {
    method: "POST",
    body,
  });
}

function encodeForm(values: object): FormData {
  const form = new FormData();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== null) form.append(key, value instanceof Blob ? value : String(value));
  }
  return form;
}

/** Exports use the same generated path and query contracts as JSON requests. */
export function download<P extends PathFor<"get">>(path: P, options:
  (Params<Operation<P, "get">, "path"> extends never ? { params?: never } : { params: Params<Operation<P, "get">, "path"> })
  & QueryOptions<Operation<P, "get">>, filename: string) {
  const params = options.params as Record<string, string | number> | undefined;
  const resolved = path.replace(/\{([^}]+)\}/g, (_, key: string) => encodeURIComponent(String(params?.[key])));
  return downloadFile(resolved.slice("/api/v1".length), options.query ?? {}, filename);
}
