import { ACMClient, ListCertificatesCommand } from "@aws-sdk/client-acm";
import type { ServiceModule, ServiceModuleFactory } from "../../core/types.js";
import { buildAcmTools } from "./tools.js";

/** AWS Certificate Manager: certificate inventory and expiry checks. */
const createAcmModule: ServiceModuleFactory = (factory) => {
  const mod: ServiceModule = {
    name: "acm",
    description: "AWS Certificate Manager (read-only): TLS certificate inventory and expiry / renewal-risk checks.",
    tools: buildAcmTools(factory),
    healthCheck: async (ctx) => {
      try {
        const { client } = factory.getClient(ACMClient, ctx.accountId, ctx.region);
        await client.send(new ListCertificatesCommand({ MaxItems: 1 }));
        return { ok: true };
      } catch (err) {
        return { ok: false, detail: String(err) };
      }
    },
  };
  return mod;
};

export default createAcmModule;
