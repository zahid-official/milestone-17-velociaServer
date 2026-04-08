import express, { Application, Request, Response } from "express";
import cors from "cors";
import passport from "passport";
import envVars from "./app/config/env";
import moduleRouter from "./app/routes";
import cookieParser from "cookie-parser";
import expressSession from "express-session";
import notFoundHandler from "./app/middlewares/notFoundHandler";
import globalErrorHandler from "./app/middlewares/globalErrorHandler";
import "./app/config/passport";

// Express application
const app: Application = express();

// Middlewares
app.use(
  expressSession({
    secret: envVars.EXPRESS_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  }),
);
app.use(passport.initialize());
app.use(passport.session());

app.use(cookieParser());
app.use(express.json());
app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: ["http://localhost:3000", `${envVars.FRONTEND_URL}`],
    credentials: true,
  }),
);

// routes middleware
app.use("/api/v1", moduleRouter);

// Root route
app.get("/", (req: Request, res: Response) => {
  res.send("Welcome to the Velocia Server");
});

// Handle global error
app.use(globalErrorHandler);

// Handle not found
app.use(notFoundHandler);

export default app;
