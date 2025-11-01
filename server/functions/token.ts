import * as jose from "jose";
import { TokenPayload } from "../interfaces.js";
import { getUserById } from "../database/functions/user.js";
import { EPOCH } from "./uid.js";
import { compareSync } from "bcrypt";

/**
 * Generates a JWT with the provided payload
 * @param password - the **RAW** password of the user
 */
export const generateAuthToken = async (
  userId: string,
  handle: string,
  password: string,
  hashedPassword: string
): Promise<string> => {
  // one year in seconds = 60 * 60 * 24 * 365
  const expiry =
    Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365 - Number(EPOCH);
  const payload: TokenPayload = {
    userId,
    handle,
    password: hashedPassword,
    exp: expiry,
  };
  const rawPassword = new TextEncoder().encode(password);

  const token = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer("Delta")
    .sign(rawPassword);
  return token;
};

// Retrieves the user from the JWT
export const getUserFromToken = async (token: string) => {
  try {
    const payload = (await jose.decodeJwt(token)) as TokenPayload;
    const user = await getUserById(payload.userId);

    if (!user) return null;
    if (payload.handle !== user.handle || payload.userId !== user.id)
      return null;

    return user;
  } catch (error) {
    console.error("Error decoding token: ", error);
    return null;
  }
};

export const AuthenticateToken = async (token: string) => {
  try {
    const payload: TokenPayload = await jose.decodeJwt(token);
    const user = await getUserById(payload.userId);
    if (!user) return false;

    if (
      payload.handle !== user.handle ||
      compareSync(payload.password, user.password)
    )
      return false;
    if (Math.floor(Date.now() / 1000) - Number(EPOCH) >= payload.exp)
      return false;
    return true;
  } catch {
    return false;
  }
};
