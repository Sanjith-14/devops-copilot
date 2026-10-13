import type { AwsClientFactory } from "../src/core/aws-client.js";

/**
 * Fake AwsClientFactory: every client's send() is answered from a map of
 * Command class name -> response (or function of the command input).
 * Unmapped commands throw, so tests fail loudly on unexpected AWS calls.
 */
export function fakeFactory(
  responses: Record<string, unknown | ((input: any) => unknown)>,
): { factory: AwsClientFactory; calls: { command: string; input: any }[] } {
  const calls: { command: string; input: any }[] = [];
  const client = {
    async send(cmd: { constructor: { name: string }; input: unknown }) {
      const name = cmd.constructor.name;
      calls.push({ command: name, input: cmd.input });
      if (!(name in responses)) throw new Error(`unexpected AWS call ${name}`);
      const r = responses[name];
      const out = typeof r === "function" ? (r as (i: unknown) => unknown)(cmd.input) : r;
      if (out instanceof Error) throw out;
      return out;
    },
  };
  const factory = { getClient: () => ({ client }) } as unknown as AwsClientFactory;
  return { factory, calls };
}

export const ctx = { accountId: "test", region: "ap-south-1" };
