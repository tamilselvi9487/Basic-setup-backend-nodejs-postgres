import config from '../../config/index.js';
import { logger } from '../../lib/winston.js';
import responseHandler from '../../utils/responseHandlers.js';
import { genUsername } from '../../utils/stringUtils.js';
import { generateAccessToken, generateRefreshToken } from '../../lib/jwt.js';
import bcrypt from 'bcrypt';
import prisma from '../../lib/prisma.js';

const register = async (req, res) => {
  const { email, password, role } = req.body;

  if (role === 'admin' && !config.WHITELIST_ADMINS_MAIL.includes(email)) {
    logger.warn(`Unauthorized admin registration attempt by ${email}`);
    return responseHandler.forbidden(res, {}, 'You cannot register as admin');
  }

  try {
    const username = genUsername();

    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
        role,
      },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
      },
    });

    const accessToken = generateAccessToken(newUser.id);
    const refreshToken = generateRefreshToken(newUser.id);

    await prisma.token.upsert({
      where: { userId: newUser.id },
      update: { token: refreshToken },
      create: { token: refreshToken, userId: newUser.id },
    });

    logger.info('Refresh token created for user', {
      userId: newUser.id,
      token: refreshToken,
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    logger.info('User registered successfully', {
      username: newUser.username,
      email: newUser.email,
      role: newUser.role,
    });

    return responseHandler.created(
      res,
      {
        user: {
          username: newUser.username,
          email: newUser.email,
          role: newUser.role,
        },
        accessToken,
      },
      'User registered successfully'
    );
  } catch (e) {
    logger.error('Error during user registration', e);
    if (e?.code === 'P2002') {
      // Prisma unique constraint violation error code
      const field = e.meta?.target?.[0] || 'field';
      logger.warn(`Duplicate key error on ${field}`);
      return responseHandler.conflict(res, e, `${field} already exists`);
    }
    return responseHandler.internalError(res, e, 'Failed to register user');
  }
};

export default register;
