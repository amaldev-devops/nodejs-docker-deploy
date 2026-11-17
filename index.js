require('dotenv').config();
const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const { SECRET_MESSAGE, USERNAME, PASSWORD } = process.env;

// Fail fast if config is missing
if (!SECRET_MESSAGE || !USERNAME || !PASSWORD) {
  console.error('Missing SECRET_MESSAGE, USERNAME or PASSWORD');
  process.exit(1);
}

// Compare strings in constant time (prevents timing attacks)
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function basicAuth(req, res, next) {
  const [scheme, encoded] = (req.headers.authorization || '').split(' ');

  if (scheme === 'Basic' && encoded) {
    const decoded = Buffer.from(encoded, 'base64').toString();
    const idx = decoded.indexOf(':');
    if (idx !== -1) {
      const user = decoded.slice(0, idx);
      const pass = decoded.slice(idx + 1);
      if (safeEqual(user, USERNAME) && safeEqual(pass, PASSWORD)) {
        return next();
      }
    }
  }

  // This header is what makes the browser show the login popup
  res.set('WWW-Authenticate', 'Basic realm="Secret Area"');
  res.status(401).send('Unauthorized: invalid username or password');
}

app.get('/', (req, res) => res.send('Hello, world!'));
app.get('/secret', basicAuth, (req, res) => res.send(SECRET_MESSAGE));

app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
