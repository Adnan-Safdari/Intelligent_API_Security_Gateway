const BASE_URL = "http://localhost:8080";

export async function login(username, password) {
  const response = await fetch(`${BASE_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await response.json().catch(() => ({}));
  return { status: response.status, ok: response.ok, data };
}

export async function getProducts() {
  const response = await fetch(`${BASE_URL}/products`);
  const data = await response.json().catch(() => ([]));
  return { status: response.status, ok: response.ok, data };
}
