/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                primary: {
                    50: '#eef2ff',
                    100: '#e0e7ff',
                    200: '#c7d2fe',
                    300: '#a5b4fc',
                    400: '#818cf8',
                    500: '#5f57ea',
                    600: '#4f46e5',
                    700: '#4338ca',
                    800: '#3730a3',
                    900: '#312e81',
                },
                success: {
                    50: '#e6fcf5',
                    100: '#d3f9e8',
                    200: '#a8f0d1',
                    300: '#7de6bb',
                    400: '#52dca4',
                    500: '#27d28d',
                    600: '#0ca678',
                    700: '#0b8c64',
                    800: '#08724f',
                    900: '#055a3c',
                },
                threat: {
                    critical: '#dc2626',
                    high: '#ea580c',
                    medium: '#f59e0b',
                    low: '#22c55e',
                    info: '#3b82f6',
                },
                surface: {
                    dark: '#111827',
                    DEFAULT: '#111827',
                    light: '#1f2937',
                }
            },
            fontFamily: {
                sans: ['Inter', 'system-ui', 'sans-serif'],
                mono: ['JetBrains Mono', 'monospace'],
            },
        },
    },
    plugins: [],
}
