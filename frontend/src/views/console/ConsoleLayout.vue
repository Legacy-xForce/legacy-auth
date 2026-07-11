<script setup lang="ts">
import { ref } from "vue";
import { RouterLink, RouterView, useRouter } from "vue-router";
import { useAuthStore } from "../../stores/auth";
import Icon from "../../components/Icon.vue";
import UserAvatar from "../../components/UserAvatar.vue";

const auth = useAuthStore();
const router = useRouter();
const menuOpen = ref(false);

const sidebarOpen = ref(false);

async function logout() {
  await auth.logout();
  router.push({ name: "login" });
}
</script>

<template>
  <div class="flex h-screen overflow-hidden">
    <div
      v-if="sidebarOpen"
      class="fixed inset-0 z-30 bg-black/60 md:hidden"
      @click="sidebarOpen = false"
    />

    <aside
      class="fixed inset-y-0 left-0 z-40 flex w-60 shrink-0 -translate-x-full flex-col border-r border-border bg-bg-elevated p-4 transition-transform duration-200 md:static md:translate-x-0"
      :class="{ 'translate-x-0': sidebarOpen }"
    >
      <div class="flex items-center gap-2.5 px-2 pb-6">
        <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-accent-soft text-accent">
          <Icon name="shield" :size="18" />
        </div>
        <div>
          <div class="text-sm font-bold">Legacy Auth</div>
          <div class="mt-1 text-[0.72rem] text-text-dim">Management Console</div>
        </div>
        <button class="icon-btn ml-auto md:hidden" @click="sidebarOpen = false">
          <Icon name="x" :size="18" />
        </button>
      </div>

      <nav class="flex flex-col gap-0.5">
        <RouterLink
          v-if="auth.isAdmin"
          :to="{ name: 'users' }"
          class="flex items-center gap-2.5 rounded-ui px-3 py-2.5 text-sm font-medium text-text-muted no-underline hover:bg-bg-hover hover:text-text"
          active-class="!bg-accent-soft !text-accent"
          @click="sidebarOpen = false"
        >
          <Icon name="users" :size="18" />
          Users
        </RouterLink>
        <RouterLink
          :to="{ name: 'settings' }"
          class="flex items-center gap-2.5 rounded-ui px-3 py-2.5 text-sm font-medium text-text-muted no-underline hover:bg-bg-hover hover:text-text"
          active-class="!bg-accent-soft !text-accent"
          @click="sidebarOpen = false"
        >
          <Icon name="settings" :size="18" />
          Settings
        </RouterLink>
      </nav>

      <div class="mt-auto flex flex-col gap-0.5 border-t border-border pt-3">
        <a href="#" class="flex items-center gap-2.5 rounded-ui px-3 py-2.5 text-sm font-medium text-text-dim no-underline hover:bg-bg-hover hover:text-text">
          <Icon name="help" :size="18" />Documentation
        </a>
        <a href="#" class="flex items-center gap-2.5 rounded-ui px-3 py-2.5 text-sm font-medium text-text-dim no-underline hover:bg-bg-hover hover:text-text">
          <Icon name="help" :size="18" />Support
        </a>
      </div>
    </aside>

    <div class="flex min-w-0 flex-1 flex-col">
      <header class="flex h-16 shrink-0 items-center justify-between gap-2 border-b border-border px-3 sm:gap-4 sm:px-6">
        <button class="icon-btn shrink-0 md:hidden" @click="sidebarOpen = true">
          <Icon name="menu" :size="20" />
        </button>
        <div class="input-wrap w-full min-w-0 sm:max-w-105">
          <Icon name="search" />
          <input class="input" placeholder="Search resources…" />
        </div>
        <div class="flex shrink-0 items-center gap-1 sm:gap-2">
          <button class="icon-btn hidden rounded-full! sm:inline-flex"><Icon name="bell" :size="18" /></button>
          <button class="icon-btn hidden rounded-full! sm:inline-flex"><Icon name="help" :size="18" /></button>
          <div class="relative">
            <button class="rounded-full border-none bg-none p-0" @click="menuOpen = !menuOpen">
              <UserAvatar v-if="auth.user" :user-id="auth.user.id" :size="32" />
            </button>
            <div
              v-if="menuOpen"
              class="card absolute right-0 top-[calc(100%+0.5rem)] z-20 min-w-45 p-2 shadow-[0_12px_24px_rgba(0,0,0,0.4)]"
              @mouseleave="menuOpen = false"
            >
              <div class="mb-1 border-b border-border px-2.5 pb-3 pt-2">
                <div class="text-sm font-semibold">{{ auth.user?.username }}</div>
                <div class="text-[0.72rem] capitalize text-text-dim">{{ auth.user?.role }}</div>
              </div>
              <button class="flex w-full items-center gap-2 rounded-ui px-2.5 py-2 text-sm text-text hover:bg-bg-hover" @click="logout">
                <Icon name="logout" :size="16" />
                Sign out
              </button>
            </div>
          </div>
        </div>
      </header>

      <main class="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
        <RouterView />
      </main>
    </div>
  </div>
</template>
