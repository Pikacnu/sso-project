export class APIError extends Error {
  statusCode: number;
  error: string;
  errorDescription?: string;

  constructor(statusCode: number, error: string, errorDescription?: string) {
    super(errorDescription || error);
    this.statusCode = statusCode;
    this.error = error;
    this.errorDescription = errorDescription;
  }
}

export async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {}),
    },
    ...options,
  });

  if (!response.ok) {
    let errorData: { error?: string; error_description?: string } = {};
    try {
      errorData = await response.json();
    } catch {
      errorData = {};
    }

    throw new APIError(
      response.status,
      errorData.error || response.statusText,
      errorData.error_description
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}
