import dotenv from 'dotenv';
import Koa from 'koa';
import Router from 'koa-router';
import bodyParser from 'koa-bodyparser';
import cors from 'koa-cors';
import authRoutes from './routes/auth';
import systemRoutes from './routes/system';

// Load environment variables
dotenv.config();

const app = new Koa();
const router = new Router();

// Middleware
app.use(cors());
app.use(bodyParser());

// Error handling middleware
app.use(async (ctx: Koa.Context, next: () => Promise<any>) => {
  try {
    await next();
  } catch (err: any) {
    ctx.status = err.status || 500;
    ctx.body = {
      success: false,
      message: err.message || 'Internal server error'
    };
    ctx.app.emit('error', err, ctx);
  }
});

router.use('/api', authRoutes.routes());
router.use('/api', systemRoutes.routes());

app.use(router.routes());
app.use(router.allowedMethods());

// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`📝 API Documentation:`);
  console.log(`   POST /api/auth/signup - User registration`);
  console.log(`   POST /api/auth/signin - User authentication`);
});

export default app;
