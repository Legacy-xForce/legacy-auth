import { createRouter, createWebHistory } from "vue-router";
import { useAuthStore } from "../stores/auth";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/login",
      name: "login",
      component: () => import("../views/LoginView.vue"),
      meta: { public: true },
    },
    {
      path: "/",
      component: () => import("../views/console/ConsoleLayout.vue"),
      redirect: { name: "users" },
      children: [
        {
          path: "users",
          name: "users",
          component: () => import("../views/console/UsersView.vue"),
          meta: { requiresAdmin: true },
        },
        {
          path: "users/new",
          name: "user-new",
          component: () => import("../views/console/UserCreateView.vue"),
          meta: { requiresAdmin: true },
        },
        {
          path: "users/:id",
          name: "user-edit",
          component: () => import("../views/console/UserEditView.vue"),
          props: true,
          meta: { requiresAdmin: true },
        },
        {
          path: "settings",
          name: "settings",
          component: () => import("../views/console/SettingsView.vue"),
        },
      ],
    },
  ],
});

router.beforeEach(async (to) => {
  const auth = useAuthStore();
  await auth.initialize();

  if (!to.meta.public && !auth.isAuthenticated) {
    return { name: "login", query: { redirect: to.fullPath } };
  }
  if (to.name === "login" && auth.isAuthenticated) {
    return { name: "users" };
  }
  if (to.meta.requiresAdmin && auth.isAuthenticated && !auth.isAdmin) {
    return { name: "settings" };
  }
  return true;
});

export default router;
