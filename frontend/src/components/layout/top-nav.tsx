import * as React from "react"
import { Bell, Search } from "lucide-react"
import { Button } from "@/components/ui/button"

export function TopNav() {
  return (
    <header className="flex h-16 items-center justify-between border-b px-6 bg-background">
      <div className="flex items-center gap-4 flex-1">
        <div className="relative w-full max-w-md hidden md:block">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            type="search"
            placeholder="Search alerts, assets, or IP addresses..."
            className="h-9 w-full rounded-md border border-input bg-background pl-9 pr-4 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          />
        </div>
      </div>
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-5 w-5" />
          <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-destructive" />
          <span className="sr-only">Notifications</span>
        </Button>
      </div>
    </header>
  )
}
