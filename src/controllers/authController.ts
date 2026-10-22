import type { Request, Response } from "express";
import { asyncHandler } from "../middleware/asyncHandler";
import { parseBody } from "../middleware/validate";
import { credentialsSchema } from "../schemas/schemas";
import type { AuthService } from "../services/authService";

export function createAuthController(authService: AuthService) {
  const register = asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = parseBody(credentialsSchema, req.body);
    const user = await authService.register(email, password);
    res.status(201).json({ user });
  });

  const login = asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = parseBody(credentialsSchema, req.body);
    const result = await authService.login(email, password);
    res.status(200).json(result);
  });

  const refresh = asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({ message: "Refresh token requerido" });
      return;
    }

    const result = await authService.refresh(refreshToken);
    res.status(200).json(result);
  });

  const logout = asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = req.body;
    authService.logout(req.auth!, refreshToken);
    res.status(200).json({ message: "Sesión cerrada" });
  });

  const me = asyncHandler(async (req: Request, res: Response) => {
    // req.auth tiene los datos descodificados del JWT pasados por requireAuth
    const userProfile = await authService.getMe(req.auth!);
    res.status(200).json(userProfile);
  });

  return { register, login, refresh, logout, me };
}