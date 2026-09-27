/**
 * API errors. Every error body is `{"code": <HTTP status>, "message": ...}`:
 * the Python E2B SDK parses it for every documented status, and the JS SDK
 * reads `code` (not the HTTP status) to recognize 404 and 409.
 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }

  body(): { code: number; message: string } {
    return { code: this.status, message: this.message };
  }
}

export const badRequest = (m: string) => new ApiError(400, m);
export const unauthorized = (m = "Invalid API key") => new ApiError(401, m);
export const forbidden = (m: string) => new ApiError(403, m);
export const notFound = (m: string) => new ApiError(404, m);
export const conflict = (m: string) => new ApiError(409, m);
export const unavailable = (m: string) => new ApiError(503, m);
export const internal = (m: string) => new ApiError(500, m);
