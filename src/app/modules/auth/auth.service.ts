import bcrypt from "bcryptjs";
import User from "../user/user.model";
import envVars from "../../config/env";
import { JwtPayload } from "jsonwebtoken";
import httpStatus from "http-status-codes";
import { verifyJWT } from "../../utils/JWT";
import AppError from "../../errors/AppError";
import { redisClient } from "../../config/redis";
import generateOtp from "../../utils/generateOtp";
import { sendEmail } from "../../utils/sendEmail";
import { generateResetToken, recreateToken } from "../../utils/getTokens";
import { AccountStatus } from "../user/user.interface";

// Regenerate access token using refresh token
const regenerateAccessToken = async (refreshToken: string) => {
  if (!refreshToken) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "No refresh token provided, authorization denied",
    );
  }

  const verifiedRefreshToken = verifyJWT(
    refreshToken,
    envVars.JWT_REFRESH_SECRET,
  ) as JwtPayload;

  // Check potential errors
  const user = await User.findOne({ email: verifiedRefreshToken.email });
  if (!user) {
    throw new AppError(httpStatus.UNAUTHORIZED, "User does not exist");
  }

  if (!user.isVerified) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "User is not verified. Please verify your email to proceed.",
    );
  }

  if (
    user.accountStatus === AccountStatus.BLOCKED ||
    user.accountStatus === AccountStatus.INACTIVE
  ) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      `User is ${user.accountStatus}. Please contact support for more information.`,
    );
  }

  if (user.isDeleted) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "User is deleted. Please contact support for more information.",
    );
  }

  // Recrete JWT access token
  const accessToken = recreateToken(user);
  return { accessToken };
};

// Account verification via OTP
const sendOTP = async (email: string) => {
  const user = await User.findOne({ email });

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  if (user.isVerified) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "User already verified. Please login",
    );
  }

  // Store otp in redis with expiry time of 2 minutes
  const otp = generateOtp(6);
  const redisKey = `otp:${email}`;
  await redisClient.set(redisKey, otp, {
    expiration: {
      type: "EX",
      value: 60 * 2,
    },
  });

  // Send otp to email
  await sendEmail({
    to: email,
    subject: "OTP code for account verification",
    templateName: "sendOtp",
    templateData: {
      otpCode: otp,
      companyName: "Velocia",
      expiryTime: "2 minutes",
    },
  });

  return null;
};

// Verify OTP and validate account
const verifyOTP = async (email: string, otp: string) => {
  const user = await User.findOne({ email });

  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  if (user.isVerified) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "User already verified. Please login",
    );
  }

  // Get otp from redis & check otp existance
  const redisKey = `otp:${email}`;
  const verifyOtp = await redisClient.get(redisKey);

  if (!verifyOtp) {
    throw new AppError(
      httpStatus.BAD_REQUEST,
      "OTP expired or invalid. Please request a new one",
    );
  }

  if (verifyOtp !== otp) {
    throw new AppError(httpStatus.BAD_REQUEST, "Invalid OTP. Please try again");
  }

  // Update user as verified and delete otp from redis
  await Promise.all([
    User.updateOne({ email }, { isVerified: true }, { runValidators: true }),
    redisClient.del(redisKey),
  ]);

  return null;
};

// Change password
const changePassword = async (
  decodedToken: JwtPayload,
  oldPassword: string,
  newPassword: string,
) => {
  const user = await User.findById(decodedToken?.userId);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  const isPasswordMatched = await bcrypt.compare(
    oldPassword,
    user.password as string,
  );
  if (!isPasswordMatched) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Old password is incorrect");
  }

  // Hash the new password and save to database
  user.password = await bcrypt.hash(newPassword, envVars.BCRYPT_SALT_ROUNDS);
  user.save();

  return null;
};

// Forgot password
const forgotPassword = async (email: string) => {
  const user = await User.findOne({ email });
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  if (!user.isVerified) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "User is not verified. Please verify your email to proceed.",
    );
  }

  if (
    user.accountStatus === AccountStatus.BLOCKED ||
    user.accountStatus === AccountStatus.INACTIVE
  ) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      `User is ${user.accountStatus}. Please contact support for more information.`,
    );
  }

  if (user.isDeleted) {
    throw new AppError(
      httpStatus.UNAUTHORIZED,
      "User is deleted. Please contact support for more information.",
    );
  }

  // Generate reset token
  const resetToken = generateResetToken(user);

  // Send password reset email
  await sendEmail({
    to: user.email,
    subject: "Password Reset Request",
    templateName: "forgotPassword",
    templateData: {
      name: user.name,
      companyName: "Velocia",
      expiryTime: "10 minutes",
      resetLink: `${envVars.FRONTEND_URL}/reset-password?id=${user._id}&accessToken=${resetToken}`,
    },
  });

  return null;
};

// Reset password
const resetPassword = async (
  userId: string,
  id: string,
  newPassword: string,
) => {
  if (userId !== id) {
    throw new AppError(httpStatus.UNAUTHORIZED, "Invalid user");
  }

  const user = await User.findById(userId);
  if (!user) {
    throw new AppError(httpStatus.NOT_FOUND, "User not found");
  }

  // Hash the new password and save to database
  const hashedPassword = await bcrypt.hash(
    newPassword,
    envVars.BCRYPT_SALT_ROUNDS,
  );
  user.password = hashedPassword;
  await user.save();

  return null;
};

// Auth service object
const authService = {
  regenerateAccessToken,
  sendOTP,
  verifyOTP,
  changePassword,
  forgotPassword,
  resetPassword,
};

export default authService;
