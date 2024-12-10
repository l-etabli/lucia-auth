import * as fs from "node:fs";
import { type Options, defineConfig } from "tsup";

type Plugin = NonNullable<Options["esbuildPlugins"]>[number];

const addJsExtensionToImports: Plugin = {
  name: "add-js-extension-to-imports",
  setup(build) {
    console.log("Reached plugin");
    build.onLoad({ filter: /\.(js|ts)$/ }, async (args) => {
      // Only process ESM format files
      console.log("In plugin");
      if (!build.initialOptions.format?.includes("esm")) return;
      console.log("ESM");

      // Read the file content
      const text = await fs.promises.readFile(args.path, "utf8");

      console.log("yolo : text is ", text);

      // Transform imports to include .js
      const code = text.replace(
        /from ['"](\.[^'"]+)['"]/g,
        (_match, importPath) => `from '${importPath}.mjs'`,
      );

      return {
        contents: code,
        loader: "ts",
      };
    });
  },
};

export default defineConfig({
  entry: ["src/**/*.ts"],
  format: ["esm", "cjs"],
  sourcemap: true,
  clean: true, // Clean the dist folder before building
  dts: true, // Generate .d.ts files
  bundle: false, // Disable bundling, to keep original source file organization
  esbuildPlugins: [addJsExtensionToImports],
  outExtension: ({ format }) => {
    if (format === "esm") return { js: ".mjs" };
    if (format === "cjs") return { js: ".cjs" };
    return { js: ".js" };
  },
});
