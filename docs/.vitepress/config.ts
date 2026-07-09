import { defineConfig } from 'vitepress'
import llmstxt from 'vitepress-plugin-llms'

// --- DEPLOY TARGET (change these two together to retarget) ---
// Deployed to Cloudflare Pages (direct-upload from CI, not CF's own build)
// and served at docs.surge.panit.dev/ via its own subdomain.
const BASE = '/'
const DOMAIN = 'https://docs.surge.panit.dev'
// -------------------------------------------------------------

export default defineConfig({
  title: 'Surge',
  description: 'Surge auth engine documentation',
  base: BASE,
  vite: {
    plugins: [llmstxt({ domain: DOMAIN })],
  },
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/introduction' },
      { text: 'Features', link: '/features/login-flows' },
      { text: 'API', link: '/api/browser/flow-init' },
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'What is Surge', link: '/guide/introduction' },
          { text: 'Quickstart', link: '/guide/quickstart' },
          { text: 'Architecture', link: '/guide/architecture' },
        ],
      },
      {
        text: 'Features',
        items: [
          { text: 'Login Flows', link: '/features/login-flows' },
          { text: 'Session Management', link: '/features/session-management' },
          { text: 'Service Authentication', link: '/features/service-authentication' },
          { text: 'Identity Management', link: '/features/identity-management' },
          { text: 'Password Authentication', link: '/features/password-authentication' },
          { text: 'Rate Limiting', link: '/features/rate-limiting' },
          { text: 'Audit Logging', link: '/features/audit-logging' },
          { text: 'CORS', link: '/features/cors' },
        ],
      },
      {
        text: 'Integration',
        items: [
          { text: 'Surge Client (Browser)', link: '/integration/surge-client' },
          { text: 'Embedding in Axum', link: '/integration/embedding' },
          { text: 'Running as a Server', link: '/integration/running-as-server' },
          { text: 'Configuration', link: '/integration/configuration' },
          { text: 'Registration Modes', link: '/integration/registration-modes' },
          { text: 'Migration', link: '/integration/migration' },
        ],
      },
      {
        text: 'API Reference',
        items: [
          {
            text: 'Browser Endpoints',
            items: [
              { text: 'Flow Init', link: '/api/browser/flow-init' },
              { text: 'Flow Complete', link: '/api/browser/flow-complete' },
              { text: 'Register', link: '/api/browser/register' },
              { text: 'Whoami', link: '/api/browser/whoami' },
              { text: 'Logout', link: '/api/browser/logout' },
            ],
          },
          {
            text: 'Service Endpoints',
            items: [
              { text: 'Session Verify', link: '/api/service/session-verify' },
              { text: 'Session Revoke', link: '/api/service/session-revoke' },
              { text: 'Identities', link: '/api/service/identity-crud' },
              { text: 'Authenticate', link: '/api/service/authenticate' },
              { text: 'Register', link: '/api/service/register' },
            ],
          },
          { text: 'Errors', link: '/api/errors' },
        ],
      },
      {
        text: 'Deployment',
        items: [
          { text: 'Docker', link: '/deployment/docker' },
          { text: 'Environment Templates', link: '/deployment/environment' },
          { text: 'Health Checks', link: '/deployment/health-checks' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Tokens', link: '/reference/tokens' },
          { text: 'CLI', link: '/reference/cli' },
          { text: 'Service Grants', link: '/reference/grants' },
          { text: 'Changelog', link: '/reference/changelog' },
        ],
      },
    ],
    socialLinks: [{ icon: 'github', link: 'https://github.com/panitdev/surge' }],
  },
})
