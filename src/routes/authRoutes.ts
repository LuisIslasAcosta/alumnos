import { Router } from "express";
import { createAuthController } from "../controllers/authController";
import { requireAuth } from "../middleware/auth";
import type { AuthService } from "../services/authService";

export function createAuthRouter(authService: AuthService): Router {
  const router = Router();
  const controller = createAuthController(authService);
  const auth = requireAuth(authService);

  router.post("/register", controller.register);
  router.post("/login", controller.login);
  router.post("/logout", auth, controller.logout);

  // Nuevo endpoint protegido para obtener mi perfil
  router.get("/me", auth, controller.me);

  return router;
}