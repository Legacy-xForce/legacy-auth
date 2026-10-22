import { createApp } from "vue";
import { createPinia } from "pinia";
import "@fontsource-variable/inter";
import "@fontsource-variable/outfit";
import "./style.css";
import App from "./App.vue";
import router from "./router";
import { useAuthStore, installApiClient } from "./stores/auth";
import { useAppearanceStore } from "./stores/appearance";

const app = createApp(App);
const pinia = createPinia();
app.use(pinia);

useAppearanceStore(pinia);
installApiClient(useAuthStore(pinia));

app.use(router);
app.mount("#app");
