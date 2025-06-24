import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Laravel Helpers",
  description: "Helpers do Laravel",
  
  locales: {
    root: {
      label: 'English',
      lang: 'en',
      title: 'Laravel Helpers',
      description: 'Complete guide to Laravel helpers'
    },
    'pt_BR': {
      label: 'Português',
      lang: 'pt-BR',
      title: 'Laravel Helpers',
      description: 'Guia completo dos helpers do Laravel'
    },
    'es': {
      label: 'Español',
      lang: 'es',
      title: 'Laravel Helpers',
      description: 'Guía completa de los helpers de Laravel'
    }
  },
  
  themeConfig: {
    socialLinks: [
      { icon: 'github', link: 'https://github.com/andrefelipe18' }
    ]
  }
})
