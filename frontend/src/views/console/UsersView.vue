<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import { api } from "../../api/client";
import type { User } from "../../stores/auth";
import Icon from "../../components/Icon.vue";
import StatusPill from "../../components/StatusPill.vue";
import UserAvatar from "../../components/UserAvatar.vue";

type ListResponse = { items: User[]; total: number; page: number; pageSize: number };

const items = ref<User[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = 10;
const search = ref("");
const role = ref<"" | "admin" | "user">("");
const loading = ref(false);

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)));

let searchDebounce: ReturnType<typeof setTimeout> | undefined;

async function load() {
  loading.value = true;
  try {
    const params = new URLSearchParams({ page: String(page.value), pageSize: String(pageSize) });
    if (search.value.trim()) params.set("q", search.value.trim());
    if (role.value) params.set("role", role.value);
    const res = await api.get<ListResponse>(`/admin/users?${params.toString()}`);
    items.value = res.items;
    total.value = res.total;
  } finally {
    loading.value = false;
  }
}

watch(search, () => {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => {
    page.value = 1;
    load();
  }, 300);
});

watch(role, () => {
  page.value = 1;
  load();
});

watch(page, load);

onMounted(load);

const rangeStart = computed(() => (total.value === 0 ? 0 : (page.value - 1) * pageSize + 1));
const rangeEnd = computed(() => Math.min(total.value, page.value * pageSize));
</script>

<template>
  <div class="flex h-full min-h-0 flex-col">
    <div class="mb-6 flex shrink-0 flex-col items-start gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 class="m-0 mb-1 text-2xl font-bold">User Management</h1>
        <p class="m-0 text-sm text-text-muted">Manage authentication identities, roles, and access controls.</p>
      </div>
      <RouterLink :to="{ name: 'user-new' }" class="btn btn-primary w-full sm:w-auto">
        <Icon name="plus" :size="16" />
        Add New User
      </RouterLink>
    </div>

    <div class="card flex min-h-0 flex-1 flex-col p-4 sm:p-5">
      <div class="mb-4 flex shrink-0 flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
        <div class="input-wrap w-full min-w-0 sm:max-w-80 sm:flex-1">
          <Icon name="search" />
          <input v-model="search" class="input" placeholder="Filter by username…" />
        </div>
        <select v-model="role" class="input w-full sm:w-auto sm:pr-8">
          <option value="">All Roles</option>
          <option value="admin">Admin</option>
          <option value="user">User</option>
        </select>
        <div class="hidden flex-1 sm:block" />
        <span class="whitespace-nowrap text-xs text-text-dim">Showing {{ rangeStart }}-{{ rangeEnd }} of {{ total }} users</span>
      </div>

      <div class="min-h-0 flex-1 overflow-auto">
        <table class="w-full min-w-135 border-collapse">
          <thead>
            <tr>
              <th class="border-b border-border px-3 py-2.5 text-left text-[0.72rem] font-semibold uppercase tracking-wider text-text-dim">Profile</th>
              <th class="border-b border-border px-3 py-2.5 text-left text-[0.72rem] font-semibold uppercase tracking-wider text-text-dim">Role</th>
              <th class="border-b border-border px-3 py-2.5 text-left text-[0.72rem] font-semibold uppercase tracking-wider text-text-dim">Status</th>
              <th class="border-b border-border px-3 py-2.5 text-right text-[0.72rem] font-semibold uppercase tracking-wider text-text-dim">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading">
              <td colspan="4" class="border-b border-border p-8 text-center text-text-dim">Loading…</td>
            </tr>
            <tr v-else-if="items.length === 0">
              <td colspan="4" class="border-b border-border p-8 text-center text-text-dim">No users found.</td>
            </tr>
            <tr v-for="user in items" :key="user.id" class="last:[&>td]:border-b-0">
              <td class="border-b border-border px-3 py-3 align-middle text-sm">
                <div class="flex items-center gap-2.5">
                  <UserAvatar :user-id="user.id" :size="36" />
                  <div>
                    <div class="font-semibold">{{ user.username }}</div>
                    <div class="font-mono text-[0.72rem] text-text-dim" :title="user.id">{{ user.id.slice(0, 8) }}&hellip;</div>
                  </div>
                </div>
              </td>
              <td class="border-b border-border px-3 py-3 align-middle text-sm">
                <span
                  class="chip"
                  :class="user.role === 'admin' ? 'bg-danger-soft text-danger' : 'bg-bg-input text-text-muted'"
                >
                  <Icon v-if="user.role === 'admin'" name="shield" :size="12" />
                  {{ user.role === "admin" ? "Admin" : "User" }}
                </span>
              </td>
              <td class="border-b border-border px-3 py-3 align-middle text-sm"><StatusPill :active="user.active" /></td>
              <td class="whitespace-nowrap border-b border-border px-3 py-3 text-right align-middle text-sm">
                <RouterLink :to="{ name: 'user-edit', params: { id: user.id } }" class="icon-btn">
                  <Icon name="pencil" :size="16" />
                </RouterLink>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="mt-5 flex shrink-0 items-center justify-center gap-4">
        <button class="btn btn-ghost" :disabled="page <= 1" @click="page--">Previous</button>
        <span class="text-[0.82rem] text-text-muted">Page {{ page }} of {{ totalPages }}</span>
        <button class="btn btn-ghost" :disabled="page >= totalPages" @click="page++">Next</button>
      </div>
    </div>
  </div>
</template>
