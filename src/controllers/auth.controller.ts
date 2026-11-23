import { randomUUID } from "node:crypto";
import type { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../../prisma/client.ts";

import type {
  RegisterInput,
  LoginInput,
  RefreshInput,
} from "../validators/auth.validator.ts";

export const login = async (
  req: Request<{}, {}, LoginInput>,
  res: Response,
) => {
  const { username, password } = req.body;

  const user = await prisma.user.findUnique({
    where: { username },
  });

  if (!user) {
    return res.status(401).json({
      error: "Invalid credentials",
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    return res.status(401).json({
      error: "Invalid credentials",
    });
  }

  const accessToken = jwt.sign(
    { sub: String(user.id) },
    process.env.JWT_SECRET!,
    { expiresIn: "15m" },
  );

  await prisma.refreshToken.deleteMany({
    where: {
      userId: user.id,
    },
  });

  const refreshToken = jwt.sign(
    {
      sub: String(user.id),
      jti: randomUUID(),
    },
    process.env.JWT_SECRET!,
    { expiresIn: "7d" },
  );

  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });

  return res.status(200).json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      name: user.name,
    },
    accessToken,
    refreshToken,
  });
};

export const register = async (
  req: Request<{}, {}, RegisterInput>,
  res: Response,
) => {
  const { username, email, password, name } = req.body;

  const existingUser = await prisma.user.findFirst({
    where: {
      OR: [{ username }, { email }],
    },
  });

  if (existingUser) {
    return res.status(409).json({
      error: "Username or email already taken",
    });
  }
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      username,
      email,
      password: hashedPassword,
      name,
    },
  });

  const accessToken = jwt.sign(
    { sub: String(user.id) },
    process.env.JWT_SECRET!,
    { expiresIn: "15m" },
  );

  const refreshToken = jwt.sign(
    {
      sub: String(user.id),
      jti: randomUUID(),
    },
    process.env.JWT_SECRET!,
    { expiresIn: "7d" },
  );

  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });

  return res.status(201).json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      name: user.name,
    },
    accessToken,
    refreshToken,
  });
};

export const refresh = async (
  req: Request<{}, {}, RefreshInput>,
  res: Response,
) => {
  const { refreshToken } = req.body;

  try {
    jwt.verify(refreshToken, process.env.JWT_SECRET!);
  } catch {
    return res.status(401).json({
      error: "Invalid or expired refresh token",
    });
  }

  const storedToken = await prisma.refreshToken.findUnique({
    where: { token: refreshToken },
  });

  if (!storedToken || storedToken.expiresAt < new Date()) {
    return res.status(401).json({
      error: "Invalid or expired refresh token",
    });
  }
};
