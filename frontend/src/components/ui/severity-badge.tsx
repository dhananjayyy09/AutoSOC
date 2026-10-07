import * as React from "react"
import { Badge, BadgeProps } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export type SeverityLevel = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

interface SeverityBadgeProps extends Omit<BadgeProps, "variant"> {
  level: SeverityLevel
}

export function SeverityBadge({ level, className, ...props }: SeverityBadgeProps) {
  const getSeverityClasses = (level: SeverityLevel) => {
    switch (level) {
      case "CRITICAL":
        return "bg-red-900 text-red-100 hover:bg-red-800 border-red-500"
      case "HIGH":
        return "bg-orange-900 text-orange-100 hover:bg-orange-800 border-orange-500"
      case "MEDIUM":
        return "bg-yellow-900 text-yellow-100 hover:bg-yellow-800 border-yellow-500"
      case "LOW":
        return "bg-green-900 text-green-100 hover:bg-green-800 border-green-500"
      case "INFO":
      default:
        return "bg-blue-900 text-blue-100 hover:bg-blue-800 border-blue-500"
    }
  }

  return (
    <Badge
      className={cn("border", getSeverityClasses(level), className)}
      {...props}
    >
      {level}
    </Badge>
  )
}
