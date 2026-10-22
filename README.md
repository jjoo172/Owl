# Owl
Provides insights into open-source directories

## Deploying to Render

The site lives in `public/` and is described by `render.yaml` as a static site.

1. In the Render dashboard, choose **New → Blueprint**.
2. Connect this repository (`jjoo172/Owl`) and select the `main` branch.
3. Render reads `render.yaml`, creates the `owl` static site, and serves it at a public `https://owl-*.onrender.com` URL.

Every push to `main` redeploys automatically.
