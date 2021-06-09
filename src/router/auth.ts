import { Router } from 'express';
import { clearSessionCookie, setSessionCookie } from '../utils/cookie';
import { serialize } from '../utils/session';
import { getDomain } from '../utils/base';
import {
  serializeAuthState,
  deserializeAuthState,
  setAuthStateCookie,
  getAuthStateCookie,
} from '../utils/state';

const router = Router();

router.get('/auth/login', function (req, res) {
  const backToPath = '/private';
  const state = serializeAuthState({ backToPath });

  // create url
  const authUrl = req.app.authClient!.authorizationUrl({
    scope: 'openid email profile',
    state,
  });

  setAuthStateCookie(res, state);

  res.redirect(authUrl);
});

router.get('/auth/callback', async (req, res, next) => {
  try {
    console.info({ cookies: req.cookies });
    const state = getAuthStateCookie(req);
    const { backToPath } = deserializeAuthState(state);
    const client = req.app.authClient;

    const params = client!.callbackParams(req); // return {code, state}
    const tokenSet = await client!.callback(
      `${getDomain()}/auth/callback`,
      params,
      { state }
    );
    const user = await client!.userinfo(tokenSet);

    const sessionCookie = serialize({ tokenSet, user });
    setSessionCookie(res, sessionCookie);

    res.redirect(backToPath);
  } catch (error) {
    console.error(`Auth callback error: ${error}`);
    return next(error);
  }
});

router.get('/auth/logout', async (req, res) => {
  const client = req.app.authClient;
  const tokenSet = req.session?.tokenSet;

  try {
    await client!.revoke(tokenSet!.access_token!);
  } catch (err) {
    console.error('error revoking access_token', err);
  }
  clearSessionCookie(res);

  res.redirect('/');
});

export default router;
