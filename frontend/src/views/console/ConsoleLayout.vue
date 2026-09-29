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
      class="fixed inset-y-0 left-0 z-40 flex w-60 shrink-0 -translate-x-full flex-col justify-between border-r border-border bg-bg-elevated p-4 transition-transform duration-200 md:static md:translate-x-0"
      :class="{ 'translate-x-0': sidebarOpen }"
    >
      <div>
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
      </div>

      <div class="relative border-t border-border pt-3">
        <button class="flex w-full items-center gap-2.5 rounded-ui px-2 py-2 hover:bg-bg-hover" @click="menuOpen = !menuOpen">
          <UserAvatar v-if="auth.user" :user-id="auth.user.id" :size="32" />
          <div class="min-w-0 text-left">
            <div class="truncate text-sm font-semibold">{{ auth.user?.username }}</div>
            <div class="truncate text-[0.72rem] capitalize text-text-dim">{{ auth.user?.role }}</div>
          </div>
        </button>
        <div
          v-if="menuOpen"
          class="card absolute bottom-[calc(100%+0.5rem)] left-0 z-20 min-w-45 p-2 shadow-[0_12px_24px_rgba(0,0,0,0.4)]"
          @mouseleave="menuOpen = false"
        >
          <button class="flex w-full items-center gap-2 rounded-ui px-2.5 py-2 text-sm text-text hover:bg-bg-hover" @click="logout">
            <Icon name="logout" :size="16" />
            Sign out
          </button>
        </div>
      </div>
    </aside>

    <div class="flex min-w-0 flex-1 flex-col">
      <header class="flex h-14 shrink-0 items-center gap-2 border-b border-border px-3 md:hidden sm:gap-4 sm:px-6">
        <button class="icon-btn shrink-0" @click="sidebarOpen = true">
          <Icon name="menu" :size="20" />
        </button>
      </header>

      <main class="flex-1 overflow-y-auto p-4 sm:p-6">
        <RouterView />
      </main>
    </div>
  </div>
</template>
