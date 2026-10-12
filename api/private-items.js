// Card 1: fail-closed endpoint. Card 3 will replace this with verified-session authorization.
// Never accept a user ID from query parameters as proof of identity.
export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.status(401).json({ error: 'AUTH_REQUIRED', message: '패스키 로그인이 필요합니다.' });
}
