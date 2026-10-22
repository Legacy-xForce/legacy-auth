import { defineStore } from "pinia";
import { ref } from "vue";

export type ToastTone = "success" | "error" | "info";

export type Toast = { id: number; tone: ToastTone; message: string };

let nextId = 1;

/** Short confirmations ("Saved", "Copied") shown in a corner and dismissed on their own. */
export const useToastStore = defineStore("toast", () => {
  const toasts = ref<Toast[]>([]);

  function dismiss(id: number) {
    toasts.value = toasts.value.filter((toast) => toast.id !== id);
  }

  function show(message: string, tone: ToastTone = "success", duration = 2800) {
    const id = nextId++;
    toasts.value = [...toasts.value.slice(-2), { id, tone, message }];
    setTimeout(() => dismiss(id), duration);
  }

  return {
    toasts,
    dismiss,
    success: (message: string) => show(message, "success"),
    error: (message: string) => show(message, "error", 4500),
    info: (message: string) => show(message, "info"),
  };
});
