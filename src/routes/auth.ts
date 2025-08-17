import Router from 'koa-router';
import { RouterContext } from 'koa-router';
import jwt from 'jsonwebtoken';
import { AuthService } from '../services/auth';
import { signupSchema, signinSchema } from '../validation/auth';
import { SignupRequest, SigninRequest } from '../types/auth';

const router = new Router({ prefix: '/auth' });
const authService = new AuthService();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const AUTH_COOKIE_KEY = process.env.AUTH_COOKIE_KEY || 'auth_token';

// Middleware to authenticate JWT token from cookies
const authenticateToken = async (ctx: RouterContext, next: () => Promise<any>) => {
  const token = ctx.cookies.get(AUTH_COOKIE_KEY);
  
  if (!token) {
    ctx.status = 401;
    ctx.body = {
      success: false,
      message: 'Access token required'
    };
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string; email: string };
    ctx.state.user = decoded;
    await next();
  } catch (error) {
    ctx.status = 403;
    ctx.body = {
      success: false,
      message: 'Invalid or expired token'
    };
  }
};

const validateRequest = (schema: any) => {
  return async (ctx: RouterContext, next: () => Promise<any>) => {
    try {
      const { error, value } = schema.validate(ctx.request.body);
      if (error) {
        ctx.status = 400;
        ctx.body = {
          success: false,
          message: 'Validation failed',
          errors: error.details.map((detail: any) => ({
            field: detail.path[0],
            message: detail.message
          }))
        };
        return;
      }
      ctx.state.validatedData = value;
      await next();
    } catch (err) {
      ctx.status = 500;
      ctx.body = {
        success: false,
        message: 'Internal server error'
      };
    }
  };
};

router.post('/signup', validateRequest(signupSchema), async (ctx: RouterContext) => {
  try {
    const userData: SignupRequest = ctx.state.validatedData;
    
    const result = await authService.signup(userData);
    
    // Set JWT token as HTTP-only cookie
    ctx.cookies.set(AUTH_COOKIE_KEY, result.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      path: '/'
    });
    
    ctx.status = 201;
    ctx.body = {
      success: true,
      message: 'User registered successfully',
      data: {
        user: result.user
      }
    };
  } catch (error: any) {
    if (error.message === 'User with this email already exists') {
      ctx.status = 409;
      ctx.body = {
        success: false,
        message: error.message
      };
    } else {
      ctx.status = 500;
      ctx.body = {
        success: false,
        message: 'Internal server error'
      };
    }
  }
});

// Signin route
router.post('/signin', validateRequest(signinSchema), async (ctx: RouterContext) => {
  try {
    const credentials: SigninRequest = ctx.state.validatedData;
    
    const result = await authService.signin(credentials);
    
    // Set JWT token as HTTP-only cookie
    ctx.cookies.set(AUTH_COOKIE_KEY, result.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      path: '/'
    });
    
    ctx.status = 200;
    ctx.body = {
      success: true,
      message: 'User signed in successfully',
      data: {
        user: result.user
      }
    };
  } catch (error: any) {
    if (error.message === 'Invalid email or password') {
      ctx.status = 401;
      ctx.body = {
        success: false,
        message: error.message
      };
    } else {
      ctx.status = 500;
      ctx.body = {
        success: false,
        message: 'Internal server error'
      };
    }
  }
});

// Logout route
router.post('/signout', async (ctx: RouterContext) => {
  // Clear the auth token cookie
  ctx.cookies.set(AUTH_COOKIE_KEY, '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 0, // Expire immediately
    path: '/'
  });
  
  ctx.status = 200;
  ctx.body = {
    success: true,
    message: 'User logged out successfully'
  };
});

// Refresh token route
router.post('/refresh', authenticateToken, async (ctx: RouterContext) => {
  try {
    const userId = ctx.state.user.userId;
    const user = await authService.getUserById(userId);
    
    if (!user) {
      ctx.status = 404;
      ctx.body = {
        success: false,
        message: 'User not found'
      };
      return;
    }
    
    // Generate new JWT token
    const newToken = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    // Set new JWT token as HTTP-only cookie
    ctx.cookies.set(AUTH_COOKIE_KEY, newToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      path: '/'
    });
    
    ctx.status = 200;
    ctx.body = {
      success: true,
      message: 'Token refreshed successfully'
    };
  } catch (error: any) {
    ctx.status = 500;
    ctx.body = {
      success: false,
      message: 'Internal server error'
    };
  }
});

// Get current user profile (protected route)
router.get('/me', authenticateToken, async (ctx: RouterContext) => {
  try {
    const userId = ctx.state.user.userId;
    const user = await authService.getUserById(userId);
    
    if (!user) {
      ctx.status = 404;
      ctx.body = {
        success: false,
        message: 'User not found'
      };
      return;
    }
    
    ctx.status = 200;
    ctx.body = {
      success: true,
      data: {
        user
      }
    };
  } catch (error: any) {
    ctx.status = 500;
    ctx.body = {
      success: false,
      message: 'Internal server error'
    };
  }
});

export default router;
