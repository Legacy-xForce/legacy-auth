import { onBeforeUnmount, ref } from "vue";
import { useToastStore } from "../stores/toast";

/**
 * Clipboard copy with the brief "Copied" confirmation. `registerCleanup` is
 * false only for tests that call it outside a component instance.
 */
export function useCopyToClipboard(duration = 1500, registerCleanup = true) {
  const copied = ref(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy(text: string, successMessage?: string): Promise<boolean> {
    if (!text) return false;
    await navigator.clipboard.writeText(text);
    copied.value = true;
    if (successMessage) useToastStore().success(successMessage);
    clearTimeout(timer);
    timer = setTimeout(() => { copied.value = false; }, duration);
    return true;
  }

  if (registerCleanup) onBeforeUnmount(() => clearTimeout(timer));
  return { copied, copy };
}
