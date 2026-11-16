import axios from "axios";

const fallbackBaseURL = typeof window !== "undefined"
  ? "/api"
  : "http://localhost:8000";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || fallbackBaseURL,
});

api.interceptors.request.use((config) => {
  const token = window.localStorage.getItem("vapt_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// When the server rejects our token (expired, revoked, user deactivated), drop it and tell the
// app once, so it returns to the sign-in screen instead of polling with a dead session.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const url = error?.config?.url || "";
    if (error?.response?.status === 401 && !url.includes("/auth/login") && window.localStorage.getItem("vapt_token")) {
      window.localStorage.removeItem("vapt_token");
      window.dispatchEvent(new CustomEvent("vapt:session-ended"));
    }
    return Promise.reject(error);
  },
);

export default api;
