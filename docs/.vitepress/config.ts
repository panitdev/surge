import { defineConfig } from 'vitepress'
import llmstxt from 'vitepress-plugin-llms'

// --- DEPLOY TARGET (change these two together to retarget) ---
// Deployed to Cloudflare Pages (direct-upload from CI, not CF's own build)
// and served at docs.panit.dev/surge/ via an org-level route/proxy that this
// repo does not own or configure. This repo only ever emits static output
// under the /surge/ base — it must never claim docs.panit.dev itself.
const BASE = '/surge/'
const DOMAIN = 'https://docs.panit.dev'
// -------------------------------------------------------------

export default defineConfig({
  title: 'Surge',
  description: 'Surge auth engine documentation',
  base: BASE,
  vite: {
    plugins: [llmstxt({ domain: DOMAIN })],
  },
  themeConfig: {
    nav: [{ text: 'Guide', link: '/guide/introduction' }],
    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'What is Surge', link: '/guide/introduction' },
          { text: 'Architecture', link: '/guide/architecture' },
        ],
      },
    ],
    socialLinks: [{ icon: 'github', link: 'https://github.com/panitdev/surge' }],
  },
})
