import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { compile } from "json-schema-to-typescript";

export async function generateApiTypes(document) {
  // OpenAPI 3.1 model schemas are JSON Schema. Adapt the surrounding HTTP
  // metadata to JSON Schema too, so the compiler can retain the existing
  // components/paths/operations type contract without the TypeScript compiler API.
  if (!document.openapi.startsWith("3.1.")) {
    throw new Error("API type generation requires OpenAPI 3.1 JSON Schema");
  }

  function object(properties, required = Object.keys(properties)) {
    return {
      type: "object",
      properties,
      required,
      additionalProperties: false,
    };
  }

  function reference(name) {
    return {
      $ref: `#/$defs/${name.replaceAll("~", "~0").replaceAll("/", "~1")}`,
    };
  }

  function resolve(value) {
    if (!value?.$ref) return value;
    if (!value.$ref.startsWith("#/")) {
      throw new Error(
        `External OpenAPI reference is unsupported: ${value.$ref}`,
      );
    }
    const resolved = value.$ref
      .slice(2)
      .split("/")
      .reduce(
        (parent, key) =>
          parent?.[key.replaceAll("~1", "/").replaceAll("~0", "~")],
        document,
      );
    if (!resolved)
      throw new Error(`Unresolved OpenAPI reference: ${value.$ref}`);
    return resolve(resolved);
  }

  function inputSchema(value) {
    if (Array.isArray(value)) return value.map(inputSchema);
    if ((value?.format === "binary" || value?.contentMediaType === "application/octet-stream")) return { ...value, tsType: "Blob" };
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries([
      ...Object.entries(value).map(([key, item]) => [key,
        key === "$ref" && item.startsWith("#/components/schemas/")
          ? item.replace("#/components/schemas/", "#/$defs/Input_")
          : inputSchema(item),
      ]),
      ...(value.properties ? [["x-guardiano-input", true]] : []),
    ]);
  }

  function content(value, input = false) {
    return object(
      Object.fromEntries(
        Object.entries(value ?? {}).map(([mediaType, media]) => [
          mediaType,
          input ? inputSchema(media.schema ?? {}) : media.schema ?? {},
        ]),
      ),
    );
  }

  function parameters(values) {
    const groups = Object.fromEntries(
      ["query", "header", "path", "cookie"].map((location) => {
        const entries = values
          .map(resolve)
          .filter((parameter) => parameter.in === location);
        return [
          location,
          entries.length
            ? object(
                Object.fromEntries(
                  entries.map((parameter) => [
                    parameter.name,
                    // Parameter requiredness comes from OpenAPI's required
                    // flag; a query default does not make it mandatory.
                    { ...parameter.schema, default: undefined },
                  ]),
                ),
                entries
                  .filter((parameter) => parameter.required)
                  .map((parameter) => parameter.name),
              )
            : false,
        ];
      }),
    );
    return object(
      groups,
      Object.keys(groups).filter((key) => groups[key]?.required?.length),
    );
  }

  const paths = {};
  const operations = {};
  const definitions = {
    ...document.components.schemas,
    ...Object.fromEntries(Object.entries(document.components.schemas).map(([name, schema]) => [`Input_${name}`, inputSchema(schema)])),
  };
  for (const [path, rawItem] of Object.entries(document.paths)) {
    const item = resolve(rawItem);
    const methods = { parameters: parameters(item.parameters ?? []) };
    for (const method of [
      "get",
      "put",
      "post",
      "delete",
      "options",
      "head",
      "patch",
      "trace",
    ]) {
      if (!item[method]) {
        methods[method] = false;
        continue;
      }
      const operation = item[method];
      const properties = {
        parameters: parameters([
          ...(item.parameters ?? []),
          ...(operation.parameters ?? []),
        ]),
        responses: object(
          Object.fromEntries(
            Object.entries(operation.responses).map(([status, rawResponse]) => {
              const response = resolve(rawResponse);
              return [
                status,
                object(
                  {
                    headers: { type: "object", additionalProperties: {} },
                    content: response.content
                      ? content(response.content)
                      : false,
                  },
                  response.content ? ["headers", "content"] : ["headers"],
                ),
              ];
            }),
          ),
        ),
        requestBody: false,
      };
      if (operation.requestBody) {
        const body = resolve(operation.requestBody);
        properties.requestBody = object({ content: content(body.content, true) });
      }
      const required = ["parameters", "responses"];
      if (resolve(operation.requestBody)?.required)
        required.push("requestBody");
      const definition = `Operation_${operation.operationId ?? `${method}_${path}`}`;
      definitions[definition] = object(properties, required);
      methods[method] = reference(definition);
      if (operation.operationId)
        operations[operation.operationId] = methods[method];
    }
    paths[path] = object(
      methods,
      Object.keys(methods).filter((key) => methods[key] !== false),
    );
  }

  const schema = {
    ...object({
      components: object({
        schemas: object(
          Object.fromEntries(
            Object.keys(document.components.schemas).map((name) => [
              name,
              reference(name),
            ]),
          ),
        ),
      }),
      paths: object(paths),
      operations: object(operations),
    }),
    $defs: definitions,
  };
  // Model references refer to the original OpenAPI document, rather than the
  // JSON Schema wrapper's properties. Keep recursive model references intact.
  const normalized = JSON.parse(JSON.stringify(schema), (key, value) => {
    // Property titles in FastAPI's schema would create thousands of redundant
    // named aliases. References already give reusable models their names.
    if (key === "title" && typeof value === "string") return undefined;
    if (key === "properties") return value;
    if (key === "$ref") {
      if (value.startsWith("#/$defs/")) return value;
      if (!value.startsWith("#/components/schemas/")) {
        throw new Error(`Unsupported model reference: ${value}`);
      }
      return value.replace("#/components/schemas/", "#/$defs/");
    }
    // Match the previous generator's defaultNonNullable behavior: properties
    // with non-null defaults are always present in the API model types.
    if (value?.properties && !value["x-guardiano-input"]) {
      value.required = [
        ...new Set([
          ...(value.required ?? []),
          ...Object.entries(value.properties)
            .filter(
              ([, property]) =>
                property.default !== undefined && property.default !== null,
            )
            .map(([name]) => name),
        ]),
      ];
    }
    return value;
  });
  const generated = await compile(normalized, "ApiContract", {
    additionalProperties: false,
    bannerComment:
      "/* biome-ignore-all lint: Generated API declarations. */\n/** Generated from openapi.json by pnpm gen:api. Do not edit. */",
    unknownAny: true,
    ignoreMinAndMaxItems: true,
    format: true,
  });
  return `${generated}\nexport type components = ApiContract["components"];\nexport type paths = ApiContract["paths"];\nexport type operations = ApiContract["operations"];\n`;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const source = new URL("../src/api/openapi.json", import.meta.url);
  const target = new URL("../src/api/schema.d.ts", import.meta.url);
  const document = JSON.parse(await readFile(source, "utf8"));
  await writeFile(target, await generateApiTypes(document));
  console.log(`Generated ${fileURLToPath(target)}`);
}
