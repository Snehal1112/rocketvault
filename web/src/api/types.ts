// ApiError mirrors the backend's real error envelope, common.AppError
// (../../../common/utils.go): {id, message, detailed_error, request_id,
// status_code, retry_after_seconds}. Verified against that file directly,
// not guessed.

/** The raw JSON shape the backend sends for every non-2xx response. */
export interface ApiErrorBody {
  id: string
  message: string
  detailed_error: string
  request_id?: string
  status_code?: number
  retry_after_seconds?: number
}

/**
 * Thrown by `request()` (src/api/client.ts) for every non-2xx response.
 * Exposes the same fields as the wire shape, camelCased for ergonomic use in
 * UI code, while the constructor accepts the wire shape directly so a parsed
 * response body can be passed straight through.
 */
export class ApiError extends Error {
  id: string
  detailedError: string
  requestId?: string
  statusCode: number
  retryAfterSeconds?: number

  constructor(body: Partial<ApiErrorBody> & { message: string }) {
    super(body.message)
    this.name = "ApiError"
    this.id = body.id ?? ""
    this.detailedError = body.detailed_error ?? ""
    this.requestId = body.request_id
    this.statusCode = body.status_code ?? 0
    this.retryAfterSeconds = body.retry_after_seconds
  }
}

/** The envelope a successful `request<T>()` call resolves to: just the body. */
export type ApiResponse<T> = T
