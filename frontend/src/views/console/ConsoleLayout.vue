<script setup lang="ts">
import { ref } from "vue";
import { RouterLink, RouterView, useRouter } from "vue-router";
import { useAuthStore } from "../../stores/auth";
import { useDismiss } from "../../composables/useDismiss";
import BrandMark from "../../components/BrandMark.vue";
import Icon from "../../components/Icon.vue";
import UserAvatar from "../../components/UserAvatar.vue";

const auth = useAuthStore();
const router = useRouter();

const menuOpen = ref(false);
const menu = ref<HTMLElement | null>(null);
useDismiss(menu, menuOpen);

async function logout() {
  menuOpen.value = false;
  await auth.logout();
  router.push({ name: "login" });
}
</script>

<template>
  <div class="flex min-h-dvh flex-col">
    <header class="sticky top-0 z-30 border-b border-line bg-canvas/80 pt-[env(safe-area-inset-top)] backdrop-blur-xl">
      <div class="mx-auto flex h-16 w-full max-w-6xl items-center gap-2 px-4 sm:gap-3 sm:px-6">
        <RouterLink :to="{ name: auth.isAdmin ? 'users' : 'settings' }" class="mr-1 flex items-center gap-2.5 text-fg no-underline sm:mr-3">
          <BrandMark class="size-6" />
          <span class="display-text hidden text-title sm:inline">Legacy <span class="text-muted">Auth</span></span>
        </RouterLink>

        <nav v-if="auth.isAdmin" class="flex items-center gap-1" aria-label="Console">
          <RouterLink
            :to="{ name: 'users' }"
            class="pressable flex h-9 items-center gap-2 rounded-full px-3.5 text-meta font-medium text-muted no-underline hover:bg-fg/6 hover:text-fg"
            active-class="!bg-fg/8 !text-fg"
          >
            <Icon name="users" :size="16" />
            Users
          </RouterLink>
          <RouterLink
            :to="{ name: 'settings' }"
            class="pressable flex h-9 items-center gap-2 rounded-full px-3.5 text-meta font-medium text-muted no-underline hover:bg-fg/6 hover:text-fg"
            active-class="!bg-fg/8 !text-fg"
          >
            <Icon name="settings" :size="16" />
            Settings
          </RouterLink>
        </nav>

        <div ref="menu" class="relative ml-auto">
          <button
            type="button"
            class="pressable flex h-10 cursor-pointer items-center gap-2.5 rounded-full py-1 pr-1 pl-1 hover:bg-fg/6 sm:pr-3.5"
            aria-haspopup="menu"
            :aria-expanded="menuOpen"
            aria-label="Account menu"
            @click="menuOpen = !menuOpen"
          >
            <UserAvatar v-if="auth.user" :user-id="auth.user.id" :name="auth.user.username" :size="32" />
            <span class="hidden max-w-40 truncate text-meta font-semibold sm:inline">{{ auth.user?.username }}</span>
          </button>

          <Transition name="pop">
            <div
              v-if="menuOpen"
              role="menu"
              class="absolute top-[calc(100%+0.5rem)] right-0 z-40 w-64 origin-top-right rounded-2xl border border-line bg-overlay p-1.5 shadow-(--shadow-overlay)"
            >
              <div class="flex items-center gap-3 px-2.5 pt-2 pb-3">
                <UserAvatar v-if="auth.user" :user-id="auth.user.id" :name="auth.user.username" :size="40" />
                <div class="min-w-0">
                  <div class="truncate text-body font-semibold">{{ auth.user?.username }}</div>
                  <div class="text-meta text-muted">{{ auth.isAdmin ? "Administrator" : "Member" }}</div>
                </div>
              </div>
              <div class="mx-1 mb-1.5 h-px bg-line" />
              <RouterLink
                :to="{ name: 'settings' }"
                role="menuitem"
                class="flex h-10 items-center gap-3 rounded-[10px] px-2.5 text-meta font-medium text-fg no-underline hover:bg-fg/6"
                @click="menuOpen = false"
              >
                <Icon name="settings" :size="16" class="text-muted" />
                Account settings
              </RouterLink>
              <button
                type="button"
                role="menuitem"
                class="flex h-10 w-full cursor-pointer items-center gap-3 rounded-[10px] px-2.5 text-meta font-medium text-fg hover:bg-fg/6"
                @click="logout"
              >
                <Icon name="logout" :size="16" class="text-muted" />
                Sign out
              </button>
            </div>
          </Transition>
        </div>
      </div>
    </header>

    <main class="mx-auto w-full max-w-6xl flex-1 px-4 pt-6 pb-16 sm:px-6 sm:pt-10">
      <RouterView v-slot="{ Component, route }">
        <Transition name="route" mode="out-in">
          <component :is="Component" :key="route.path" />
        </Transition>
      </RouterView>
    </main>
  </div>
</template>
