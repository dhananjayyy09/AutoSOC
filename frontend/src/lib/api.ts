export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export class ApiClient {
  static async get(endpoint: string, options: RequestInit = {}) {
    const url = `${API_BASE_URL}${endpoint}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.statusText}`);
    }
    
    return response.json();
  }
}

export const checkHealth = async () => {
  try {
    const res = await ApiClient.get("/health", { cache: "no-store" });
    return { status: "connected", data: res };
  } catch (error) {
    return { status: "unavailable", error };
  }
};
