/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      screens: {
        // Custom breakpoint the Layout navbar uses: below 1100px the
        // twelve top-level nav items no longer fit on one line, so the
        // header collapses into a hamburger. Chosen by measurement,
        // not a Tailwind default.
        nav: '1100px',
      },
    },
  },
  plugins: [],
};
