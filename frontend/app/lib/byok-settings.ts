export const OPENROUTER_SETTINGS_STORAGE_KEY = "skillspector-openrouter-settings-v1";
export const DEFAULT_OPENROUTER_MODEL = "~openai/gpt-latest";

export interface OpenRouterSettings {
  apiKey: string;
  model: string;
}

export function defaultOpenRouterSettings(): OpenRouterSettings {
  return {
    apiKey: "",
    model: DEFAULT_OPENROUTER_MODEL,
  };
}

export function loadOpenRouterSettings(): OpenRouterSettings {
  if (typeof window === "undefined") {
    return defaultOpenRouterSettings();
  }

  try {
    const raw = window.localStorage.getItem(OPENROUTER_SETTINGS_STORAGE_KEY);
    if (!raw) return defaultOpenRouterSettings();
    const parsed = JSON.parse(raw) as Partial<OpenRouterSettings>;
    return {
      apiKey: typeof parsed.apiKey === "string" ? parsed.apiKey : "",
      model:
        typeof parsed.model === "string" && parsed.model.trim().length > 0
          ? parsed.model.trim()
          : DEFAULT_OPENROUTER_MODEL,
    };
  } catch {
    return defaultOpenRouterSettings();
  }
}

export function saveOpenRouterSettings(settings: OpenRouterSettings): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(OPENROUTER_SETTINGS_STORAGE_KEY, JSON.stringify(settings));
}
