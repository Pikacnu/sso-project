/**
 * Check if user is authenticated by trying to access protected API
 */
export async function checkAuth(): Promise<boolean> {
  try {
    const response = await fetch("/api/user", {
      credentials: "include",
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Logout and redirect to login page
 */
export async function logout(): Promise<void> {
  try {
    await fetch("/auth/logout", {
      method: "GET",
      credentials: "include",
    });
  } catch (error) {
    console.error("Logout failed:", error);
  } finally {
    window.location.href = "/login";
  }
}

/**
 * Handle 401 errors and redirect to login
 */
export function handleUnauthorized(): void {
  window.location.href = "/login";
}
