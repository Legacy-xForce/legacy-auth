<script setup lang="ts">
import BrandMark from "./BrandMark.vue";
import ThemeMenu from "./ThemeMenu.vue";

// The frame of every signed-out page: the mark, a title, one card, and the theme switch.
defineProps<{ title: string }>();
</script>

<template>
  <div class="relative isolate flex min-h-dvh flex-col overflow-x-hidden">
    <div
      class="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[32rem]"
      style="
        background: radial-gradient(42rem 24rem at 50% -6rem, color-mix(in oklab, var(--color-accent) 15%, transparent), transparent 72%);
      "
      aria-hidden="true"
    />

    <header class="flex justify-end px-4 pt-[max(1rem,env(safe-area-inset-top))] sm:px-6 sm:pt-6">
      <ThemeMenu />
    </header>

    <main class="flex flex-1 flex-col items-center px-5 pt-4 pb-10 sm:pt-[9vh]">
      <div class="w-full max-w-100 animate-rise-in">
        <div class="mb-7 flex flex-col items-center text-center">
          <div
            class="flex size-14 items-center justify-center rounded-2xl border border-accent/25 bg-accent/10 text-fg shadow-[0_0_40px_-6px_color-mix(in_oklab,var(--color-accent)_45%,transparent)]"
          >
            <BrandMark class="size-7" />
          </div>
          <h1 class="m-0 mt-5 text-display text-fg">{{ title }}</h1>
          <slot name="subtitle" />
        </div>

        <slot />
      </div>
    </main>

    <footer class="px-6 pb-[max(1.5rem,env(safe-area-inset-bottom))] text-center text-xs text-subtle">
      One Legacy account for the calendar and the tracker.
    </footer>
  </div>
</template>
