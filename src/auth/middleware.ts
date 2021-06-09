import { Request, NextFunction, Response } from 'express';
import { Issuer } from 'openid-client';
import { getDomain } from '../utils/base';
import {
  clearSessionCookie,
  getSessionCookie,
  setSessionCookie,
} from '../utils/cookie';
import { deserialize, serialize } from '../utils/session';

export async function initialize(
  req: Request,
  res: Response,
  next: NextFunction
) {
  if (req.app.authClient) {
    return next();
  }

  const googleIssuer = await Issuer.discover('https://accounts.google.com');
  // console.info({ googleIssuer, metadata: googleIssuer.metadata });
  console.info('OpendId issuer created');
  const client = new googleIssuer.Client({
    client_id: process.env.OAUTH_CLIENT_ID!,
    client_secret: process.env.OAUTH_CLIENT_SECRET!,
    redirect_uris: [`${getDomain()}/auth/callback`],
    response_types: ['code'],
  });

  req.app.authIssuer = googleIssuer;
  req.app.authClient = client;

  next();
}

export async function session(req: Request, res: Response, next: NextFunction) {
  const sessionCookie = getSessionCookie(req);
  if (!sessionCookie) {
    // No logged-in yet,
    return next();
  }

  const client = req.app.authClient;
  const session = deserialize(sessionCookie);

  if (session.tokenSet.expired()) {
    try {
      const refreshedTokenSet = await client!.refresh(session.tokenSet);
      session.tokenSet = refreshedTokenSet;
      setSessionCookie(res, serialize(session));
    } catch (err) {
      clearSessionCookie(res);
      return next();
    }
  }

  // validate token
  const validate = req.app.authClient?.validateIdToken as any;
  try {
    await validate.call(client, session.tokenSet);
  } catch (err) {
    console.info('bad token signature found in auth cookie');
    return next(new Error('Bad Token in Auth Cookie!'));
  }

  req.session = session;

  next();
}
