import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { generateApiTypes } from "./gen-api.mjs";

const fixture = {
  openapi: "3.1.0",
  components: {
    schemas: {
      Model: {
        type: "object",
        properties: {
          title: { title: "Title", type: "string" },
          note: { anyOf: [{ type: "string" }, { type: "null" }] },
          count: { type: "integer", default: 0 },
          tags: { type: "array", items: { type: "string" }, maxItems: 2 },
          state: { type: "string", enum: ["open", "closed"] },
          child: { $ref: "#/components/schemas/Model" },
        },
        required: ["title", "note", "state"],
      },
    },
  },
  paths: {
    "/models/{id}": {
      parameters: [
        { in: "path", name: "id", required: true, schema: { type: "integer" } },
      ],
      post: {
        operationId: "createModel",
        parameters: [
          {
            in: "query",
            name: "limit",
            schema: { type: "integer", default: 10 },
          },
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: { $ref: "#/components/schemas/Model" },
            },
          },
        },
        responses: {
          201: {
            content: {
              "application/json": {
                schema: {
                  anyOf: [
                    { $ref: "#/components/schemas/Model" },
                    { type: "null" },
                  ],
                },
              },
            },
          },
          204: { description: "No content" },
        },
      },
    },
  },
};

test("generated declarations preserve model and HTTP contracts under TypeScript 7", async () => {
  const directory = await mkdtemp(join(tmpdir(), "guardiano-api-types-"));
  try {
    const generated = await generateApiTypes(fixture);
    assert.equal(
      generated,
      await generateApiTypes(fixture),
      "generation must be deterministic",
    );
    await writeFile(join(directory, "schema.d.ts"), generated);
    await writeFile(
      join(directory, "check.ts"),
      `
import type { components, paths, operations } from "./schema";
type Model = components["schemas"]["Model"];
const model: Model = { title: "test", note: null, count: 0, state: "open", tags: ["a", "b", "c"] };
const recursive: Model = { ...model, child: model };
// @ts-expect-error A non-null default remains required, matching the previous generator.
const missingDefault: Model = { title: "test", note: null, state: "open" };
// @ts-expect-error Enum members must remain constrained.
const invalidEnum: Model = { ...model, state: "unknown" };
type Post = paths["/models/{id}"]["post"];
const body: Post["requestBody"]["content"]["application/json"] = recursive;
const defaultsOptional: Post["requestBody"]["content"]["application/json"] = { title: "test", note: null, state: "open", child: { title: "child", note: null, state: "closed" } };
const response: Post["responses"][201]["content"]["application/json"] = null;
const operationBody: operations["createModel"]["requestBody"]["content"]["application/json"] = body;
const parameters: Post["parameters"] = { path: { id: 1 }, query: {} };
// @ts-expect-error Path parameters remain mandatory.
const missingPath: Post["parameters"] = {};
// @ts-expect-error A 204 response has no JSON body.
const emptyResponse: Post["responses"][204]["content"] = {};
// @ts-expect-error Unsupported HTTP methods remain forbidden.
const unsupportedMethod: paths["/models/{id}"]["delete"] = {};
// @ts-expect-error Required request body fields must remain checked.
const invalidBody: Post["requestBody"]["content"]["application/json"] = {};
// @ts-expect-error Unknown endpoints must not become legal paths.
type UnknownPath = paths["/missing"];
`,
    );
    execFileSync(
      fileURLToPath(new URL("../node_modules/.bin/tsc", import.meta.url)),
      [
        "--ignoreConfig",
        "--noEmit",
        "--strict",
        "--skipLibCheck",
        "--target",
        "es2022",
        "--module",
        "esnext",
        "--moduleResolution",
        "bundler",
        join(directory, "check.ts"),
      ],
      { stdio: "pipe" },
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("unsupported OpenAPI dialects and model references fail explicitly", async () => {
  await assert.rejects(
    generateApiTypes({ ...fixture, openapi: "3.0.3" }),
    /OpenAPI 3.1/,
  );
  const unsupported = structuredClone(fixture);
  unsupported.components.schemas.Model.properties.child.$ref =
    "external.json#/Model";
  await assert.rejects(
    generateApiTypes(unsupported),
    /Unsupported model reference/,
  );
});
