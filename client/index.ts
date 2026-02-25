import {
  ClawShieldPlugin,
  type ClawShieldPluginApi,
  type ClawShieldPluginConfig,
} from "./src/ohttp-shield.plugin.ts";

export { ClawShieldPlugin } from "./src/ohttp-shield.plugin.ts";

export default function register(api: ClawShieldPluginApi): void {
  const cfg = (api?.pluginConfig ?? {}) as Partial<ClawShieldPluginConfig>;
  const plugin = new ClawShieldPlugin(api, cfg);
  plugin.registerRoutes();
}
