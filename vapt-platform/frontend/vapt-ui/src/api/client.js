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

export default api;
