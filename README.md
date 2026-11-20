# MuteGram — API starter

This is the first backend foundation for MuteGram, not the complete game release.

## Included
- Virtual-number registration (`+7...`) and password login
- Password hashing with PBKDF2-HMAC-SHA256
- Bearer-token sessions and logout
- Account profile endpoint
- Change primary number to a virtual `+888...` number
- Phone-number history
- Admin lookup and star adjustment protected by `MUTEGRAM_ADMIN_KEY`
- Health endpoint for Render

## Important before public launch
This starter uses SQLite. Render's free service filesystem is ephemeral, so accounts and balances can be lost on restart/redeploy. **Do not invite real players or treat this as the production database.** Before public release, connect a persistent PostgreSQL database (for example Supabase) and migrate the schema. The Pygame client also still needs to be connected to these API endpoints; this server alone does not make the current game online.

The `+7` and `+888` numbers are virtual in-game identifiers, not real phone numbers and cannot receive SMS.

## Deploy on Render
1. Upload these files to the root of the GitHub repository `MuteGram`.
2. In Render choose New > Web Service and select that repository.
3. Use the included `render.yaml` Blueprint settings, or set:
   - Build command: `pip install -r requirements.txt`
   - Start command: `python -c "from server import init_db; init_db()" && gunicorn server:app --bind 0.0.0.0:$PORT`
4. Confirm the instance is Free. Do not add a paid disk.
5. Render creates `MUTEGRAM_ADMIN_KEY` automatically from `render.yaml`. Keep it private.

## API quick test
- `GET /health`
- `POST /api/register` JSON: `{"phone":"+77777777777","password":"your-password","name":"Player"}`
- `POST /api/login` JSON: `{"phone":"+77777777777","password":"your-password"}`
- Authenticated requests: header `Authorization: Bearer <token>`

Use HTTPS in production. Never share passwords, tokens, or the admin key.
