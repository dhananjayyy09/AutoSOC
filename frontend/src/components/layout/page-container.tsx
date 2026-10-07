import * as React from "react"
import { cn } from "@/lib/utils"

interface PageContainerProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string
  description?: string
  children: React.ReactNode
}

export function PageContainer({ title, description, children, className, ...props }: PageContainerProps) {
  return (
    <div className={cn("flex-1 space-y-4 p-8 pt-6", className)} {...props}>
      {(title || description) && (
        <div className="flex flex-col space-y-1.5 pb-4">
          {title && <h2 className="text-3xl font-bold tracking-tight">{title}</h2>}
          {description && <p className="text-muted-foreground">{description}</p>}
        </div>
      )}
      {children}
    </div>
  )
}
