import {
  createRootRoute,
  createRoute,
  createRouter,
  redirect,
} from "@tanstack/react-router";

import { ActivityPage } from "./activity/activity-page";
import { AuthorizationsPage } from "./authorizations/authorizations-page";
import { NotFoundPage } from "./components/common";
import { ManagementPage } from "./management/management-page";
import { RequestsPage } from "./requests/requests-page";
import { RootLayout } from "./shell/root-layout";

const rootRoute = createRootRoute({
  component: RootLayout,
  notFoundComponent: NotFoundPage,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: () => {
    throw redirect({ to: "/requests" });
  },
});

const requestsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/requests",
  component: RequestsPage,
});

const activityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/activity",
  component: ActivityPage,
});

const authorizationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/authorizations",
  component: AuthorizationsPage,
});

const managementRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/management",
  component: ManagementPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  requestsRoute,
  activityRoute,
  authorizationsRoute,
  managementRoute,
]);

export const router = createRouter({
  routeTree,
  defaultPreload: "intent",
  defaultPreloadStaleTime: 0,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
