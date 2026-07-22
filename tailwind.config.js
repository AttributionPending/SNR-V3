/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: [
    './index.html',
    './src/**/*.{ts,tsx,js,jsx}',
  ],
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
        // Neutral scale, driven by CSS vars so navy-* classes flip light/dark.
        navy: {
          950: 'hsl(var(--n-950) / <alpha-value>)',
          900: 'hsl(var(--n-900) / <alpha-value>)',
          800: 'hsl(var(--n-800) / <alpha-value>)',
          700: 'hsl(var(--n-700) / <alpha-value>)',
          600: 'hsl(var(--n-600) / <alpha-value>)',
        },
        // Accent scale (restrained professional blue), driven by CSS vars so
        // cyan-* classes flip light/dark. Full 50–950 so every used shade maps.
        cyan: {
          50:  'hsl(var(--a-50) / <alpha-value>)',
          100: 'hsl(var(--a-100) / <alpha-value>)',
          200: 'hsl(var(--a-200) / <alpha-value>)',
          300: 'hsl(var(--a-300) / <alpha-value>)',
          400: 'hsl(var(--a-400) / <alpha-value>)',
          500: 'hsl(var(--a-500) / <alpha-value>)',
          600: 'hsl(var(--a-600) / <alpha-value>)',
          700: 'hsl(var(--a-700) / <alpha-value>)',
          800: 'hsl(var(--a-800) / <alpha-value>)',
          900: 'hsl(var(--a-900) / <alpha-value>)',
          950: 'hsl(var(--a-950) / <alpha-value>)',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      keyframes: {
        'accordion-down': {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' },
        },
        pulse: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.5' },
        },
      },
      animation: {
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up': 'accordion-up 0.2s ease-out',
        'pulse-slow': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
}
