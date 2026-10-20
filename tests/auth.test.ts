import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import type { Express } from "express";
import { buildTestApp } from "./helpers";
import { config } from "../src/config/env";

describe("Autenticación", () => {
  let app: Express;

  beforeEach(() => {
    app = buildTestApp();
  });

  it("registra un usuario nuevo (201)", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ email: "ana@test.com", password: "secret123" });
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({ email: "ana@test.com" });
    expect(res.body.user.id).toBeTypeOf("number");
  });

  it("rechaza correo inválido o contraseña corta (400)", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ email: "no-es-correo", password: "123" });
    expect(res.status).toBe(400);
    expect(res.body.details).toBeInstanceOf(Array);
  });

  it("rechaza registro duplicado (409)", async () => {
    await request(app)
      .post("/api/auth/register")
      .send({ email: "dup@test.com", password: "secret123" });
    const res = await request(app)
      .post("/api/auth/register")
      .send({ email: "dup@test.com", password: "secret123" });
    expect(res.status).toBe(409);
  });

  it("inicia sesión y devuelve un token (200)", async () => {
    await request(app)
      .post("/api/auth/register")
      .send({ email: "log@test.com", password: "secret123" });
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "log@test.com", password: "secret123" });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTypeOf("string");
  });

  it("incluye nombre y correo en el payload del token", async () => {
    await request(app).post("/api/students").send({
      nombre: "Ana",
      apellido: "López",
      matricula: "A100",
      email: "student@test.com",
      password: "secret123",
    });

    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "student@test.com", password: "secret123" });

    const payload = jwt.verify(login.body.token, config.jwtSecret) as {
      nombre?: string;
      email?: string;
    };

    expect(payload.nombre).toBe("Ana López");
    expect(payload.email).toBe("student@test.com");
  });

  it("rechaza credenciales incorrectas (401)", async () => {
    await request(app)
      .post("/api/auth/register")
      .send({ email: "bad@test.com", password: "secret123" });
    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "bad@test.com", password: "wrongpass" });
    expect(res.status).toBe(401);
  });

  it("invalida el token tras logout (401 en peticiones posteriores)", async () => {
    await request(app)
      .post("/api/auth/register")
      .send({ email: "out@test.com", password: "secret123" });
    const login = await request(app)
      .post("/api/auth/login")
      .send({ email: "out@test.com", password: "secret123" });
    const token = login.body.token as string;

    const logout = await request(app)
      .post("/api/auth/logout")
      .set("Authorization", `Bearer ${token}`);
    expect(logout.status).toBe(200);

    const after = await request(app)
      .get("/api/students")
      .set("Authorization", `Bearer ${token}`);
    expect(after.status).toBe(401);
  });
});
