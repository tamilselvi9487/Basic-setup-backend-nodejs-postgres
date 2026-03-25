import jwt from 'jsonwebtoken';
import responseHandler from '../../utils/responseHandlers.js';
import { generateAccessToken, verifyRefreshToken } from '../../lib/jwt.js';
import { logger } from '../../lib/winston.js';
import prisma from '../../lib/prisma.js';

export const refreshToken = async (req, res) => {
  const token = req.cookies.refreshToken;

  try {
    // Check if the refresh token exists in the database
    const tokenExists = await prisma.token.findFirst({
      where: { token },
    });

    if (!tokenExists) {
      return responseHandler.unauthorized(
        res,
        { code: 'AuthenticationError' },
        'Invalid refresh token'
      );
    }

    // Verify and decode the refresh token payload
    const jwtPayload = verifyRefreshToken(token);
    const newAccessToken = generateAccessToken(jwtPayload.userId);

    responseHandler.ok(res, { newAccessToken });
  } catch (e) {
    if (e instanceof jwt.TokenExpiredError) {
      return responseHandler.unauthorized(
        res,
        { code: 'AuthenticationError' },
        'Refresh token expired, Please login again'
      );
    }

    if (e instanceof jwt.JsonWebTokenError) {
      return responseHandler.unauthorized(
        res,
        { code: 'AuthenticationError' },
        'Access token invalid'
      );
    }

    logger.error('Error during refresh token', e);
    responseHandler.internalError(res, e);
  }
};
