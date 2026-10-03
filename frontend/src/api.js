const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/+$/, '');

export function apiFetch(path, options) {
  return fetch(`${apiBaseUrl}${path}`, options);
}