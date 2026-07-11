import { createApp } from "vue";
import { createPinia } from "pinia";
import "./style.css";
import App from "./App.vue";
import router from "./router";
import { useAuthStore, installApiClient } from "./stores/auth";

const app = createApp(App);
const pinia = createPinia();
app.use(pinia);

installApiClient(useAuthStore(pinia));

app.use(router);
app.mount("#app");
