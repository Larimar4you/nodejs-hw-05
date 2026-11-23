import { validateBody } from "../middleware/validate.ts";

import { RegisterSchema, LoginSchema } from "../validators/auth.validator.ts";
import { Router } from "express";
import { register, login } from "../controllers/auth.controller.ts";

const router = Router();

router.post("/register", validateBody(RegisterSchema), register);

router.post("/login", validateBody(LoginSchema), login);

export default router;
