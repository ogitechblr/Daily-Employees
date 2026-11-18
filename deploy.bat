@echo off
cd /d %~dp0
echo === OGI free deploy to Cloudflare (needs Node.js) ===
call npx wrangler login
call npx wrangler d1 create ogi-db
echo.
set /p DBID=Paste the database_id shown above and press Enter: 
powershell -Command "(Get-Content wrangler.toml) -replace 'PASTE-YOUR-D1-DATABASE-ID-HERE','%DBID%' | Set-Content wrangler.toml"
call npx wrangler deploy
echo.
echo Now type any long random text for SESSION_SECRET when asked:
call npx wrangler secret put SESSION_SECRET
echo.
echo Done. Open the workers.dev address printed above.
pause
