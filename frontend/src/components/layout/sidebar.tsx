"use client"

import * as React from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { 
  Shield, 
  LayoutDashboard, 
  Bell, 
  ShieldAlert, 
  Search, 
  BrainCircuit,
  Crosshair,
  Server,
  Activity,
  FileText,
  Settings
} from "lucide-react"
import { cn } from "@/lib/utils"

const navigation = [
  { name: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { name: "Alerts", href: "/alerts", icon: Bell },
  { name: "Incidents", href: "/incidents", icon: ShieldAlert },
  { name: "Investigations", href: "/investigations", icon: Search },
  { name: "Threat Intelligence", href: "/threat-intelligence", icon: BrainCircuit },
  { name: "Threat Hunting", href: "/threat-hunting", icon: Crosshair },
  { name: "MITRE ATT&CK", href: "/mitre", icon: Shield },
  { name: "Agents", href: "/agents", icon: Server },
  { name: "Audit Logs", href: "/audit", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()

  return (
    <div className="flex h-full w-64 flex-col border-r bg-sidebar text-sidebar-foreground">
      <div className="flex h-16 items-center border-b px-6">
        <Link href="/" className="flex items-center gap-2 font-bold tracking-tight text-lg text-primary">
          <Activity className="h-6 w-6" />
          <span>AutoSOC</span>
        </Link>
      </div>
      <div className="flex-1 overflow-auto py-4">
        <nav className="grid gap-1 px-4">
          {navigation.map((item) => {
            const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`)
            return (
              <Link
                key={item.name}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive 
                    ? "bg-primary/10 text-primary" 
                    : "text-muted-foreground hover:bg-sidebar-hover hover:text-foreground"
                )}
              >
                <item.icon className={cn("h-4 w-4", isActive ? "text-primary" : "text-muted-foreground")} />
                {item.name}
              </Link>
            )
          })}
        </nav>
      </div>
      <div className="border-t p-4">
        <div className="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground">
          <div className="h-8 w-8 rounded-full bg-muted flex items-center justify-center">
            <span className="text-xs font-bold text-foreground">OP</span>
          </div>
          <div className="flex flex-col">
            <span className="font-medium text-foreground">SOC Operator</span>
            <span className="text-xs">Level 1 Analyst</span>
          </div>
        </div>
      </div>
    </div>
  )
}
