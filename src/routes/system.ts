import Router from 'koa-router';
import { Context } from 'koa';

const router = new Router({ prefix: '/system' });

router.get('/health', (ctx) => {
  ctx.body = {
    success: true,
    message: 'Koa TypeScript Auth API is running',
    timestamp: new Date().toISOString()
  };
});

export default router;
