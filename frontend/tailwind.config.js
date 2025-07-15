/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html"
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          primary: '#1e3a8a',
          secondary: '#3730a3',
          accent: '#06b6d4',
          success: '#10b981',
          warning: '#f59e0b',
          danger: '#ef4444',
          dark: '#0f172a',
          'dark-light': '#1e293b',
          'dark-medium': '#334155',
        },
        security: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#ca8a04',
          low: '#16a34a',
          info: '#2563eb',
        }
      },
      fontFamily: {
        'cyber': ['Inter', 'system-ui', 'sans-serif'],
        'mono': ['JetBrains Mono', 'Monaco', 'Courier New', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'bounce-slow': 'bounce 2s infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'matrix': 'matrix 20s linear infinite',
        'cyber-grid': 'cyber-grid 10s linear infinite',
      },
      keyframes: {
        glow: {
          'from': {
            boxShadow: '0 0 20px rgba(6, 182, 212, 0.3)',
          },
          'to': {
            boxShadow: '0 0 30px rgba(6, 182, 212, 0.6), 0 0 40px rgba(6, 182, 212, 0.3)',
          },
        },
        matrix: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'cyber-grid': {
          '0%': { transform: 'translateX(0) translateY(0)' },
          '100%': { transform: 'translateX(-50px) translateY(-50px)' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
      backgroundImage: {
        'cyber-gradient': 'linear-gradient(135deg, #1e3a8a 0%, #3730a3 50%, #1e40af 100%)',
        'threat-gradient': 'linear-gradient(135deg, #dc2626 0%, #ef4444 100%)',
        'success-gradient': 'linear-gradient(135deg, #059669 0%, #10b981 100%)',
        'warning-gradient': 'linear-gradient(135deg, #d97706 0%, #f59e0b 100%)',
        'grid-pattern': `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='40' height='40' viewBox='0 0 40 40'%3E%3Cg fill='%23334155' fill-opacity='0.1'%3E%3Cpath d='m0 40 40-40h-40z'/%3E%3C/g%3E%3C/svg%3E")`,
      },
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '128': '32rem',
      },
      borderRadius: {
        'xl': '1rem',
        '2xl': '1.5rem',
        '3xl': '2rem',
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(6, 182, 212, 0.3)',
        'cyber-lg': '0 0 30px rgba(6, 182, 212, 0.4), 0 10px 25px rgba(0, 0, 0, 0.2)',
        'threat': '0 0 20px rgba(239, 68, 68, 0.3)',
        'success': '0 0 20px rgba(16, 185, 129, 0.3)',
        'glass': '0 8px 32px rgba(15, 23, 42, 0.3)',
      },
      screens: {
        'xs': '475px',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
  ],
}