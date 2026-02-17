import { defineMiddleware } from "astro:middleware";

export const onRequest = defineMiddleware(async (context,next) => {
  const url = new URL(context.request.url);
  const pathname = url.pathname;
  if (PathNameInfoTable[pathname]) {
    context.locals.title = PathNameInfoTable[pathname].title;
    context.locals.description = PathNameInfoTable[pathname].description;
  }
  return next();
})

const PathNameInfoTable:Record<string,{
  title:string;
  description:string;
}> = {
  "/": {
    title: "Home - SSO Server",
    description: "A Single Sign-On (SSO) server built with Go, OAuth2, and OpenID Connect."
  },
  "/login" :{
    title: "Login - SSO Server",
    description: "Login page for the SSO Server. Use email or OAuth providers to sign in."
  },
  "/panel/clients": {
    title: "OAuth Clients - SSO Server",
    description: "Manage OAuth clients, secrets, and redirect URIs."
  },
  "/panel/users": {
    title: "Users - SSO Server",
    description: "Manage users and access details in the SSO system."
  },
  "/panel/roles": {
    title: "Roles - SSO Server",
    description: "Create and manage roles used for authorization."
  },
  "/panel/permissions": {
    title: "Permissions - SSO Server",
    description: "Define and manage permission scopes for the platform."
  }
}