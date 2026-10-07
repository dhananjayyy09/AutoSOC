import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { HealthCheck } from "@/components/health-check"
import { Activity } from "lucide-react"

export default function LoginPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4">
      <div className="mb-8 flex items-center gap-2 text-primary">
        <Activity className="h-10 w-10" />
        <span className="text-3xl font-bold tracking-tight">AutoSOC</span>
      </div>
      
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <CardTitle className="text-2xl font-bold">SOC Operator Login</CardTitle>
          <CardDescription>
            Enter your credentials to access the autonomous platform
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">Email</div>
            <input 
              type="email" 
              placeholder="operator@autosoc.local" 
              className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50" 
            />
          </div>
          <div className="space-y-2">
            <div className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">Password</div>
            <input 
              type="password" 
              className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50" 
            />
          </div>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button className="w-full">Sign In</Button>
          <div className="text-sm text-muted-foreground text-center">
            (Authentication is not implemented yet)
          </div>
        </CardFooter>
      </Card>
      
      <div className="mt-8">
        <HealthCheck />
      </div>
    </div>
  )
}
