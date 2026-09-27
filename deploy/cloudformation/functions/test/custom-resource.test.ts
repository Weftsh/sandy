import type { CloudFormationCustomResourceEvent, Context } from "aws-lambda";
import { describe, expect, it, vi } from "vitest";

import { buildResponse, customResource, stringList, withIamPropagationRetry } from "../src/shared/custom-resource.js";

const create: CloudFormationCustomResourceEvent = {
  RequestType: "Create",
  ServiceToken: "x",
  ResponseURL: "https://cloudformation-custom-resource-response.example.com/presigned",
  StackId: "arn:aws:cloudformation:us-east-1:111122223333:stack/weft/1",
  RequestId: "req-1",
  LogicalResourceId: "Thing",
  ResourceType: "Custom::Thing",
  ResourceProperties: { ServiceToken: "x" },
};
const update: CloudFormationCustomResourceEvent = { ...create, RequestType: "Update", PhysicalResourceId: "phys-1", OldResourceProperties: { ServiceToken: "x" } };

function context(remainingMs = 60_000): Context {
  return { logStreamName: "2026/09/27/[$LATEST]abc", getRemainingTimeInMillis: () => remainingMs } as unknown as Context;
}

describe("buildResponse", () => {
  it("reports success with data", () => {
    const body = JSON.parse(buildResponse(create, context(), { ok: true, result: { physicalResourceId: "p", data: { A: "1" } } }));
    expect(body).toEqual({
      Status: "SUCCESS",
      PhysicalResourceId: "p",
      StackId: create.StackId,
      RequestId: "req-1",
      LogicalResourceId: "Thing",
      Data: { A: "1" },
    });
  });

  it("keeps the existing physical ID when an update fails, so CloudFormation does not replace the resource", () => {
    const body = JSON.parse(buildResponse(update, context(), { ok: false, error: "boom" }));
    expect(body.Status).toBe("FAILED");
    expect(body.PhysicalResourceId).toBe("phys-1");
    expect(body.Reason).toMatch(/^boom \(log stream: /);
  });

  it("uses a synthetic physical ID when a create fails", () => {
    expect(JSON.parse(buildResponse(create, context(), { ok: false, error: "x" })).PhysicalResourceId).toBe("failed-create-req-1");
  });

  it("fails instead of exceeding the 4 KB response limit", () => {
    const body = JSON.parse(buildResponse(create, context(), { ok: true, result: { physicalResourceId: "p", data: { A: "x".repeat(5000) } } }));
    expect(body.Status).toBe("FAILED");
    expect(body.Reason).toMatch(/4096-byte limit/);
  });
});

describe("customResource", () => {
  it("always answers CloudFormation, including when the handler throws", async () => {
    const send = vi.fn(async () => {});
    await customResource(async () => {
      throw new Error("nope");
    }, send)(create, context());
    expect(send).toHaveBeenCalledOnce();
    const [url, body] = send.mock.calls[0] as unknown as [string, string];
    expect(url).toBe(create.ResponseURL);
    expect(JSON.parse(body).Status).toBe("FAILED");
  });

  it("answers before the Lambda times out", async () => {
    vi.useFakeTimers();
    const send = vi.fn(async () => {});
    const pending = customResource(() => new Promise(() => {}), send)(create, context(15_000));
    await vi.advanceTimersByTimeAsync(6_000);
    await pending;
    vi.useRealTimers();
    expect(JSON.parse((send.mock.calls[0] as unknown as [string, string])[1]).Reason).toMatch(/timed out/);
  });
});

describe("stringList", () => {
  it("drops the empty entries CloudFormation produces for empty list parameters", () => {
    expect(stringList({ L: ["", " a ", "b"] }, "L")).toEqual(["a", "b"]);
    expect(stringList({}, "L")).toEqual([]);
    expect(() => stringList({ L: "a" }, "L")).toThrow();
  });
});

describe("withIamPropagationRetry", () => {
  const denied = Object.assign(new Error("not yet"), { name: "AccessDeniedException" });

  it("retries AccessDenied until the policy propagates", async () => {
    let calls = 0;
    const result = await withIamPropagationRetry(async () => {
      if (++calls < 3) throw denied;
      return "ok";
    }, 5, 1);
    expect(result).toBe("ok");
    expect(calls).toBe(3);
  });

  it("gives up after the last attempt and never retries other errors", async () => {
    await expect(withIamPropagationRetry(async () => Promise.reject(denied), 3, 1)).rejects.toThrow("not yet");
    let calls = 0;
    await expect(
      withIamPropagationRetry(async () => {
        calls++;
        throw new Error("NoSuchKey");
      }, 5, 1),
    ).rejects.toThrow("NoSuchKey");
    expect(calls).toBe(1);
  });
});
