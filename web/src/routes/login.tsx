import { createRoute } from "@tanstack/react-router"

import { LoginForm } from "@/components/auth/login-form"
import { BrandLockup } from "@/components/landing/brand"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { rootRoute } from "@/routes/__root"

function LoginPage() {
  return (
    <div className="flex min-h-svh items-center justify-center bg-background p-6">
      <Card className="w-full max-w-sm">
        <CardHeader className="flex flex-col items-center gap-3 text-center">
          <BrandLockup />
          <CardTitle className="text-lg">Sign in</CardTitle>
        </CardHeader>
        <CardContent>
          <LoginForm />
        </CardContent>
      </Card>
    </div>
  )
}

export const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: LoginPage,
})
