/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        darkbg: '#090a0f',
        darkcard: '#11131a',
        darkborder: '#1f2433',
        cybercyan: '#06b6d4',
        cyberemerald: '#10b981',
        cyberrose: '#f43f5e',
      }
    },
  },
  plugins: [],
}

