import {
  ClawShieldPlugin,
  type ClawShieldPluginApi,
  type ClawShieldPluginConfig,
} from "./src/ohttp-shield.plugin.ts";

export { ClawShieldPlugin } from "./src/ohttp-shield.plugin.ts";

export default async function register(api: ClawShieldPluginApi): Promise<void> {
  const cfg = (api?.pluginConfig ?? {}) as Partial<ClawShieldPluginConfig>;
  const plugin = new ClawShieldPlugin(api, cfg);
  await plugin.registerRoutes();
}
