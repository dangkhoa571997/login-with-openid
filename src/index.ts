import express, { Response } from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import * as auth from './auth/middleware';
import router from './router/auth';
import { deserialize } from './utils/session';

dotenv.config();

const app = express();

console.info(`
 USING
 HOST: ${process.env.HOST}
 PORT: ${process.env.PORT}
 OAUTH_CLIENT_ID: ${process.env.OAUTH_CLIENT_ID}
 OAUTH_CLIENT_secret: ${process.env.OAUTH_CLIENT_SECRET}
`);

app.use(cookieParser());
app.use(auth.initialize);
app.use(auth.session);
app.use(router);

app.get('/', (_, res: Response) => {
  return res.status(200).send('Hello OpenID!');
});

app.get('/private', (req, res) => {
  const claims = req.session?.tokenSet?.claims();
  if (!claims) return res.redirect('/');
  
  res.status(200).json({
    email: claims?.email,
    name: claims?.name,
    picture: claims?.picture,
  });
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`🚀 Server ready at: http://localhost:${port}`);
});
