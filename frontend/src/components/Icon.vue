<script setup lang="ts">
import type { Component } from "vue";
import {
  ArrowLeft,
  ArrowRight,
  AtSign,
  CalendarDays,
  Camera,
  Check,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Copy,
  Dices,
  Eye,
  EyeOff,
  Fingerprint,
  Info,
  KeyRound,
  LoaderCircle,
  Lock,
  LogOut,
  MapPin,
  Palette,
  Pencil,
  Plus,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  User,
  UserPlus,
  Users,
  X,
} from "lucide-vue-next";

const props = withDefaults(defineProps<{ name: string; size?: number; strokeWidth?: number }>(), { size: 16, strokeWidth: 2 });

// Bundled with the app, so icons render on the first paint without a network request.
const icons: Record<string, Component> = {
  alertCircle: CircleAlert,
  alertTriangle: TriangleAlert,
  arrowLeft: ArrowLeft,
  arrowRight: ArrowRight,
  at: AtSign,
  calendar: CalendarDays,
  camera: Camera,
  check: Check,
  checkCircle: CircleCheck,
  chevronLeft: ChevronLeft,
  chevronRight: ChevronRight,
  copy: Copy,
  dice: Dices,
  eye: Eye,
  eyeOff: EyeOff,
  fingerprint: Fingerprint,
  info: Info,
  key: KeyRound,
  loader: LoaderCircle,
  lock: Lock,
  logout: LogOut,
  mapPin: MapPin,
  palette: Palette,
  pencil: Pencil,
  plus: Plus,
  search: Search,
  settings: Settings,
  shield: Shield,
  shieldCheck: ShieldCheck,
  trash: Trash2,
  user: User,
  userPlus: UserPlus,
  users: Users,
  x: X,
};

if (import.meta.env.DEV && !icons[props.name]) console.warn(`Unknown icon "${props.name}"`);
</script>

<template>
  <component
    :is="icons[name] ?? CircleAlert"
    :size="size"
    :stroke-width="strokeWidth"
    :class="{ 'animate-spin': name === 'loader' }"
    aria-hidden="true"
  />
</template>
