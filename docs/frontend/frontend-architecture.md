# Frontend Architecture: AutoSOC

## Overview
This document outlines the architectural decisions, component structure, and design system for the AutoSOC frontend. It's built with Next.js 15, TypeScript, Tailwind CSS, and uses a custom component library inspired by shadcn/ui.

## 1. Routing Strategy
The application uses the Next.js App Router (`app/`).
- **`/login`**: Standalone authentication view.
- **`(dashboard)/`**: All authenticated routes are wrapped in a dashboard layout.
  - `/dashboard`: Main overview.
  - `/alerts`: Real-time triage.
  - `/incidents`: Escalated cases.
  - `/investigations`: Deep dive threat correlations.
  - `/threat-intelligence`: IoC management.
  - `/threat-hunting`: Proactive querying.
  - `/mitre`: ATT&CK framework mapping.
  - `/agents`: Multi-agent AI configuration.
  - `/audit`: Security logging.
  - `/settings`: Platform configuration.

## 2. Component Organization
- **`src/components/ui/`**: Reusable, pure presentational components (Buttons, Cards, Badges, Tables, etc.).
- **`src/components/layout/`**: Application shell components (Sidebar, TopNav, PageContainer).
- **`src/components/`**: Feature-specific or composite components (e.g., `health-check.tsx`).

## 3. API Client Abstraction
A lightweight API client wrapper (`src/lib/api.ts`) handles common HTTP requests, using `fetch` with standard headers. It utilizes the environment variable `NEXT_PUBLIC_API_BASE_URL` to route requests to the Python backend.

## 4. Design System
The UI utilizes a professional, dark-mode-first aesthetic suited for a SOC environment.
- **Colors**: Slate/Zinc/Neutral backgrounds. Distinct semantic colors for severities (INFO, LOW, MEDIUM, HIGH, CRITICAL).
- **Typography**: Inter/Geist font family.
- **Micro-animations**: Subtle pulsing for live statuses, clean hover states.
- Avoids overly "flashy AI" generic styles; focuses on high information density, readability, and immediate threat visibility.

## 5. Future Real-Time Strategy
- Future updates will migrate standard polling to WebSockets or Server-Sent Events (SSE) for instant alert delivery.
- State management will likely involve a lightweight global store (like Zustand) to handle real-time AI agent status updates and live attack graphs without prop-drilling.
