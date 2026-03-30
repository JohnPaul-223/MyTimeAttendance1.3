# Supabase Setup

1. Create a new Supabase project for `TimeAttendance2`.
2. Open the SQL Editor in that new project and run [`supabase-setup.sql`](./supabase-setup.sql).
3. Open [`supabase-config.js`](./supabase-config.js) and paste your new project's URL and anon key.
4. Optional: if you want the `Email All Links` button to send messages automatically, also set either `employeeLinkEmailFunctionName` for a deployed Supabase Edge Function or `employeeLinkEmailWebhookUrl` for your own email webhook.
5. In Supabase Auth settings, keep email/password sign-in enabled for admin access.
6. Open `index.html` and create the first admin account from the `Create First Admin` tab.
7. After admin login, create employee profiles from the admin settings panel, then use the Monitoring tab to generate and email employee attendance links.
8. Employees open their own link on their own phone. The first phone that uses the link becomes the saved device for that employee.

Notes:

- This version is designed so only admins use email/password login.
- Employees do not sign up. They use admin-generated attendance links instead.
- Regenerating or revoking a link removes the old device binding for that employee.
- If you already set up Supabase before a new app update, rerun [`supabase-setup.sql`](./supabase-setup.sql) so new columns and policies such as DTR verification are added to your project.
- If you see an error like `function digest(text, unknown) does not exist`, rerun [`supabase-setup.sql`](./supabase-setup.sql). That refreshes the database functions so they can resolve `pgcrypto` correctly in Supabase.
- Automatic email delivery cannot come directly from the browser by itself. Use a Supabase Edge Function or your own webhook for the `Email All Links` button.
- Do not place a Supabase service role key in the browser.
