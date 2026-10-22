<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import { api } from "../../api/client";
import { useAuthStore, type User } from "../../stores/auth";
import { useToastStore } from "../../stores/toast";
import Icon from "../../components/Icon.vue";
import SegmentedControl from "../../components/SegmentedControl.vue";
import StatusPill from "../../components/StatusPill.vue";
import UserAvatar from "../../components/UserAvatar.vue";

type ListResponse = { items: User[]; total: number; page: number; pageSize: number };

const auth = useAuthStore();
const toast = useToastStore();

const items = ref<User[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = 10;
const search = ref("");
const role = ref<"" | "admin" | "user">("");
const loading = ref(false);
const loaded = ref(false);

const roleOptions: { value: "" | "admin" | "user"; label: string }[] = [
  { value: "", label: "All" },
  { value: "admin", label: "Admins" },
  { value: "user", label: "Members" },
];

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)));
const filtered = computed(() => Boolean(search.value.trim() || role.value));

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
  } catch (err) {
    toast.error(err instanceof Error ? err.message : "Couldn't load users");
  } finally {
    loading.value = false;
    loaded.value = true;
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

function clearFilters() {
  search.value = "";
  role.value = "";
}

// UUID copy
const copiedId = ref<string | null>(null);
async function copyId(id: string) {
  await navigator.clipboard.writeText(id);
  copiedId.value = id;
  toast.success("User ID copied");
  setTimeout(() => { copiedId.value = null; }, 1500);
}
</script>

<template>
  <div class="mx-auto flex max-w-5xl flex-col gap-6">
    <header class="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 class="m-0 flex items-baseline gap-2.5 text-display">
          Users
          <span v-if="loaded" class="tabular text-headline font-medium text-subtle">{{ total }}</span>
        </h1>
        <p class="m-0 mt-1 text-body text-muted">Everyone who can sign in to the Legacy apps.</p>
      </div>
      <RouterLink :to="{ name: 'user-new' }" class="btn btn-primary">
        <Icon name="userPlus" :size="16" />
        New user
      </RouterLink>
    </header>

    <div class="flex flex-col gap-3 sm:flex-row sm:items-center">
      <div class="input-wrap w-full sm:max-w-sm sm:flex-1">
        <Icon name="search" />
        <input
          v-model="search"
          class="input"
          enterkeyhint="search"
          placeholder="Search by username"
          aria-label="Search by username"
          autofocus
          autocomplete="off"
          data-form-type="other"
          data-lpignore="true"
          data-1p-ignore
          readonly
          @focus="($event.target as HTMLInputElement).removeAttribute('readonly')"
        />
      </div>
      <SegmentedControl v-model="role" :options="roleOptions" label="Role" class="w-full sm:w-auto" />
    </div>

    <section class="card overflow-hidden" aria-label="Users">
      <div
        class="eyebrow hidden grid-cols-[minmax(0,1fr)_7.5rem_7rem_1.25rem] items-center gap-4 border-b border-line px-5 py-3 sm:grid"
        aria-hidden="true"
      >
        <span>User</span>
        <span>Role</span>
        <span>Status</span>
        <span />
      </div>

      <ul v-if="!loaded" class="m-0 list-none divide-y divide-line p-0" aria-busy="true">
        <li v-for="n in 4" :key="n" class="flex items-center gap-3 px-4 py-3.5 sm:px-5">
          <span class="size-10 animate-pulse rounded-full bg-fg/8" />
          <span class="flex flex-col gap-2">
            <span class="h-3 w-28 animate-pulse rounded-full bg-fg/8" />
            <span class="h-2.5 w-44 animate-pulse rounded-full bg-fg/5" />
          </span>
        </li>
      </ul>

      <div v-else-if="items.length === 0" class="flex flex-col items-center px-6 py-14 text-center">
        <div class="flex size-12 items-center justify-center rounded-full bg-fg/6 text-muted">
          <Icon name="search" :size="20" />
        </div>
        <h2 class="m-0 mt-4 text-title">{{ filtered ? "No users match" : "No users yet" }}</h2>
        <p class="m-0 mt-1 text-meta text-muted">
          {{ filtered ? "Try another name, or show every role." : "Add the first account to get started." }}
        </p>
        <button v-if="filtered" type="button" class="btn btn-secondary btn-sm mt-5" @click="clearFilters">Clear filters</button>
      </div>

      <ul
        v-else
        class="m-0 list-none divide-y divide-line p-0 transition-opacity duration-200"
        :class="{ 'opacity-60': loading }"
      >
        <li
          v-for="user in items"
          :key="user.id"
          class="group relative grid grid-cols-[minmax(0,1fr)_1.25rem] items-center gap-4 px-4 py-3 transition-colors hover:bg-fg/3 sm:grid-cols-[minmax(0,1fr)_7.5rem_7rem_1.25rem] sm:px-5"
        >
          <div class="flex min-w-0 items-center gap-3">
            <UserAvatar :user-id="user.id" :name="user.username" :size="40" />
            <div class="min-w-0">
              <div class="flex min-w-0 items-center gap-2">
                <RouterLink
                  :to="{ name: 'user-edit', params: { id: user.id } }"
                  class="truncate font-semibold text-fg no-underline after:absolute after:inset-0 after:content-['']"
                >
                  {{ user.username }}
                </RouterLink>
                <span v-if="user.id === auth.user?.id" class="chip h-5 shrink-0 bg-fg/6 px-2 text-[0.6875rem] text-muted">You</span>
              </div>
              <div class="mt-1 flex items-center gap-2 sm:hidden">
                <span v-if="user.role === 'admin'" class="chip h-5 bg-accent/12 px-2 text-[0.6875rem] text-accent">Admin</span>
                <StatusPill :active="user.active" class="h-5 px-2 text-[0.6875rem]" />
              </div>
              <button
                type="button"
                class="relative z-10 mt-0.5 hidden max-w-full cursor-pointer items-center gap-1.5 rounded font-mono text-xs text-subtle transition-colors hover:text-muted sm:flex"
                :title="copiedId === user.id ? 'Copied' : 'Copy user ID'"
                :aria-label="`Copy the user ID of ${user.username}`"
                @click="copyId(user.id)"
              >
                <span class="truncate">{{ user.id }}</span>
                <Icon
                  :name="copiedId === user.id ? 'check' : 'copy'"
                  :size="12"
                  class="shrink-0 opacity-0 transition-opacity group-hover:opacity-100"
                  :class="{ 'text-success opacity-100': copiedId === user.id }"
                />
              </button>
            </div>
          </div>

          <div class="hidden sm:block">
            <span v-if="user.role === 'admin'" class="chip bg-accent/12 text-accent">
              <Icon name="shieldCheck" :size="13" />
              Admin
            </span>
            <span v-else class="chip bg-fg/6 text-muted">Member</span>
          </div>
          <div class="hidden sm:block"><StatusPill :active="user.active" /></div>
          <Icon name="chevronRight" :size="18" class="text-subtle transition-transform group-hover:translate-x-0.5 group-hover:text-fg" />
        </li>
      </ul>

      <footer
        v-if="loaded && total > 0"
        class="flex items-center justify-between gap-4 border-t border-line px-4 py-2.5 sm:px-5"
      >
        <span class="tabular text-meta text-muted">{{ rangeStart }}–{{ rangeEnd }} of {{ total }}</span>
        <div v-if="totalPages > 1" class="flex items-center gap-1">
          <span class="tabular mr-2 text-meta text-subtle">Page {{ page }} of {{ totalPages }}</span>
          <button type="button" class="icon-btn" :disabled="page <= 1" aria-label="Previous page" @click="page--">
            <Icon name="chevronLeft" :size="18" />
          </button>
          <button type="button" class="icon-btn" :disabled="page >= totalPages" aria-label="Next page" @click="page++">
            <Icon name="chevronRight" :size="18" />
          </button>
        </div>
      </footer>
    </section>
  </div>
</template>
