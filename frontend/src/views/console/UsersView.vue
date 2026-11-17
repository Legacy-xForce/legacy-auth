<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import { api } from "../../api/client";
import { useAuthStore, type User } from "../../stores/auth";
import { useToastStore } from "../../stores/toast";
import { useCopyToClipboard } from "../../composables/useCopyToClipboard";
import { errorMessage } from "../../utils/errors";
import { ROLE_FILTER_OPTIONS, type Role } from "../../constants";
import EmptyState from "../../components/EmptyState.vue";
import Icon from "../../components/Icon.vue";
import RoleChip from "../../components/RoleChip.vue";
import SegmentedControl from "../../components/SegmentedControl.vue";
import SkeletonRow from "../../components/SkeletonRow.vue";
import StatusPill from "../../components/StatusPill.vue";
import UserAvatar from "../../components/UserAvatar.vue";

type ListResponse = { items: User[]; total: number; page: number; pageSize: number };

const auth = useAuthStore();
const toast = useToastStore();
const { copy } = useCopyToClipboard();

const items = ref<User[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = 10;
const search = ref("");
const role = ref<"" | Role>("");
const loading = ref(false);
const loaded = ref(false);

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
    toast.error(errorMessage(err, "Couldn't load users"));
  } finally {
    loading.value = false;
    loaded.value = true;
  }
}

// One fetch per action: filter changes reset to page 1 and load once; page
// buttons load explicitly. No watch on `page`, so resetting it cannot double-fetch.
watch([search, role], () => {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => {
    page.value = 1;
    load();
  }, 300);
});

onMounted(load);
onBeforeUnmount(() => clearTimeout(searchDebounce));

function goToPage(next: number) {
  page.value = next;
  load();
}

const rangeStart = computed(() => (total.value === 0 ? 0 : (page.value - 1) * pageSize + 1));
const rangeEnd = computed(() => Math.min(total.value, page.value * pageSize));

function clearFilters() {
  search.value = "";
  role.value = "";
}

const copiedId = ref<string | null>(null);
async function copyId(id: string) {
  if (await copy(id, "User ID copied")) {
    copiedId.value = id;
    setTimeout(() => { if (copiedId.value === id) copiedId.value = null; }, 1500);
  }
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
          placeholder="Search by name or username"
          aria-label="Search by name or username"
          autofocus
          autocomplete="off"
          data-form-type="other"
          data-lpignore="true"
          data-1p-ignore
          readonly
          @focus="($event.target as HTMLInputElement).removeAttribute('readonly')"
        />
      </div>
      <SegmentedControl v-model="role" :options="ROLE_FILTER_OPTIONS" label="Role" class="w-full sm:w-auto" />
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
          <SkeletonRow />
        </li>
      </ul>

      <EmptyState
        v-else-if="items.length === 0"
        icon="search"
        :title="filtered ? 'No users match' : 'No users yet'"
        :description="filtered ? 'Try another name, or show every role.' : 'Add the first account to get started.'"
        :action-label="filtered ? 'Clear filters' : ''"
        @action="clearFilters"
      />

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
            <UserAvatar :user-id="user.id" :name="user.display_name || user.username" :size="40" />
            <div class="min-w-0">
              <div class="flex min-w-0 items-center gap-2">
                <RouterLink
                  :to="{ name: 'user-edit', params: { id: user.id } }"
                  class="truncate font-semibold text-fg no-underline after:absolute after:inset-0 after:content-['']"
                >
                  {{ user.display_name || user.username }}
                </RouterLink>
                <span v-if="user.id === auth.user?.id" class="chip h-5 shrink-0 bg-fg/6 px-2 text-[0.6875rem] text-muted">You</span>
              </div>
              <div class="mt-0.5 truncate text-meta text-subtle">@{{ user.username }}</div>
              <div class="mt-1 flex items-center gap-2 sm:hidden">
                <RoleChip :role="user.role" compact />
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

          <div class="hidden sm:block"><RoleChip :role="user.role" /></div>
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
          <button type="button" class="icon-btn" :disabled="page <= 1" aria-label="Previous page" @click="goToPage(page - 1)">
            <Icon name="chevronLeft" :size="18" />
          </button>
          <button type="button" class="icon-btn" :disabled="page >= totalPages" aria-label="Next page" @click="goToPage(page + 1)">
            <Icon name="chevronRight" :size="18" />
          </button>
        </div>
      </footer>
    </section>
  </div>
</template>
