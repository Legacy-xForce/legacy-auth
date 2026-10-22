import { onBeforeUnmount, onMounted, type Ref } from "vue";

/** Closes a menu or popover on a click outside `root` or on Escape. */
export function useDismiss(root: Ref<HTMLElement | null>, open: Ref<boolean>) {
  function onPointerDown(event: PointerEvent) {
    if (open.value && root.value && !root.value.contains(event.target as Node)) open.value = false;
  }

  function onKeyDown(event: KeyboardEvent) {
    if (open.value && event.key === "Escape") {
      open.value = false;
      root.value?.querySelector<HTMLElement>("[aria-haspopup]")?.focus();
    }
  }

  onMounted(() => {
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
  });
  onBeforeUnmount(() => {
    document.removeEventListener("pointerdown", onPointerDown);
    document.removeEventListener("keydown", onKeyDown);
  });
}
