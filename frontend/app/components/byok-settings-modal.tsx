"use client";

import { useEffect, useState } from "react";
import { listOpenRouterModels, type OpenRouterModelResponse } from "@/app/lib/api";
import {
  DEFAULT_OPENROUTER_MODEL,
  loadOpenRouterSettings,
  saveOpenRouterSettings,
  type OpenRouterSettings,
} from "@/app/lib/byok-settings";
import { AlertIcon, CheckIcon, CloseIcon, KeyIcon, SpinnerIcon } from "@/app/components/icons";

type CatalogState = "loading" | "ready" | "error";

export function ByokSettingsModal({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: (settings: OpenRouterSettings) => void;
}) {
  const [apiKey, setApiKey] = useState(() => loadOpenRouterSettings().apiKey);
  const [model, setModel] = useState(() => loadOpenRouterSettings().model);
  const [saved, setSaved] = useState(false);
  const [catalogState, setCatalogState] = useState<CatalogState>("loading");
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [models, setModels] = useState<OpenRouterModelResponse[]>([]);

  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);

    let cancelled = false;
    listOpenRouterModels()
      .then((response) => {
        if (!cancelled) {
          setModels(response.items);
          setCatalogState("ready");
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setCatalogError(err instanceof Error ? err.message : "Couldn't load OpenRouter models.");
          setCatalogState("error");
        }
      });

    return () => {
      cancelled = true;
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [onClose]);

  function handleSave(event: React.FormEvent) {
    event.preventDefault();
    const settings: OpenRouterSettings = {
      apiKey: apiKey.trim(),
      model: model.trim() || DEFAULT_OPENROUTER_MODEL,
    };
    saveOpenRouterSettings(settings);
    window.dispatchEvent(new StorageEvent("storage", { key: "skillspector-openrouter-settings-v1" }));
    onSaved(settings);
    setSaved(true);
    window.setTimeout(() => onClose(), 700);
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-foreground/40 px-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="byok-settings-title"
        onClick={(event) => event.stopPropagation()}
        className="max-h-[85vh] w-full max-w-md overflow-y-auto rounded-card border border-border bg-card p-6 shadow-[0_8px_40px_-8px_rgba(0,0,0,0.3)]"
      >
        <div className="flex items-center justify-between">
          <h2 id="byok-settings-title" className="text-base font-semibold text-foreground">
            OpenRouter settings
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="text-muted-foreground transition-colors duration-150 hover:text-foreground"
          >
            <CloseIcon className="h-4 w-4" />
          </button>
        </div>
        <p className="mt-1 text-sm text-muted-foreground">
          Used only for optional agent review. Stored in this browser only.
        </p>

        <form onSubmit={handleSave}>
          <div className="mt-5">
            <label htmlFor="modal-api-key" className="mb-2 block text-sm font-medium text-foreground">
              OpenRouter API key
            </label>
            <div className="relative">
              <KeyIcon className="pointer-events-none absolute left-4 top-1/2 h-4.5 w-4.5 -translate-y-1/2 text-muted-foreground" />
              <input
                id="modal-api-key"
                name="apiKey"
                type="password"
                autoComplete="off"
                autoFocus
                placeholder="sk-or-v1-…"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                className="w-full rounded-xl border border-border bg-background py-3 pl-11 pr-4 text-[15px] text-foreground placeholder:text-muted-foreground transition-colors duration-150 focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25"
              />
            </div>
          </div>

          <div className="mt-5">
            <label htmlFor="modal-model" className="mb-2 block text-sm font-medium text-foreground">
              OpenRouter model
            </label>
            <input
              id="modal-model"
              name="model"
              list="modal-openrouter-models"
              value={model}
              onChange={(event) => setModel(event.target.value)}
              placeholder={DEFAULT_OPENROUTER_MODEL}
              className="w-full rounded-xl border border-border bg-background px-4 py-3 text-[15px] text-foreground placeholder:text-muted-foreground transition-colors duration-150 focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/25"
            />
            <datalist id="modal-openrouter-models">
              {models.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </datalist>

            {catalogState === "loading" && (
              <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
                <SpinnerIcon className="h-4 w-4 animate-spin text-accent" />
                Loading models…
              </div>
            )}
            {catalogState === "error" && (
              <div className="mt-3 flex items-start gap-2 rounded-xl bg-danger-bg px-3 py-2.5 text-sm text-danger">
                <AlertIcon className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{catalogError}</span>
              </div>
            )}
          </div>

          <button
            type="submit"
            className="mt-6 flex w-full items-center justify-center gap-2 rounded-full bg-accent px-5 py-3 text-sm font-medium text-accent-foreground transition-colors duration-150 hover:bg-accent-hover"
          >
            {saved ? (
              <>
                <CheckIcon className="h-4 w-4" />
                Saved
              </>
            ) : (
              "Save settings"
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
