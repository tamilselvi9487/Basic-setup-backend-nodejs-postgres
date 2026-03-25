import responseHandler from '../../utils/responseHandlers.js';
import { generateAccessToken, generateRefreshToken } from '../../lib/jwt.js';
import config from '../../config/index.js';
import { logger } from '../../lib/winston.js';
import bcrypt from 'bcrypt';
import prisma from '../../lib/prisma.js';

const login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        username: true,
        email: true,
        password: true,
        role: true,
      },
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return responseHandler.notFound(
        res,
        { code: 'AuthError' },
        'User not found or Invalid Credentials'
      );
    }

    const accessToken = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id);

    await prisma.token.upsert({
      where: { userId: user.id },
      update: { token: refreshToken },
      create: { token: refreshToken, userId: user.id },
    });

    logger.info('Refresh token created for user', {
      userId: user.id,
      token: refreshToken,
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    responseHandler.ok(
      res,
      {
        user: {
          username: user.username,
          email: user.email,
          role: user.role,
        },
        accessToken,
      },
      'User logged in successfully'
    );
  } catch (err) {
    logger.error('Error during user login', err);
    responseHandler.internalError(res, err);
  }
};

export default login;
