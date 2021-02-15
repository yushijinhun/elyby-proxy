# elyby-proxy
Use [Ely.by](https://ely.by/) as an [authlib-injector](https://github.com/yushijinhun/authlib-injector) authentication server.

**This is an experimental project. Don't use it in production.**

# Demo server
[elyby.yushi.moe](https://elyby.yushi.moe/) is the official demo server.

This server only forwards requests to Ely.by authentication server, and will not collect or store your data.

# Deployment
This service is built with [Cloudflare Workers](https://workers.cloudflare.com/).
If you want to deploy your own service instance, please follow the steps below:
1. Login to Cloudflare
2. Go to `Workers > Manage KV namespaces`, then create a KV namespace
3. Go to `Workers > Create a Worker`
4. Copy the content of [index.js](https://github.com/yushijinhun/elyby-proxy/blob/master/index.js), and paste it to `Script` window, then click `Save and Deploy`
5. Go back to the worker page, open `Settings` tab, click `Add binding`
    * Variable name: `KV_ELYBY_PROXY`
    * KV namespace: the KV namespace you created in the 2nd step

# Known issues
* Skins can't be loaded when the client uses authlib-injector while the server doesn't.
