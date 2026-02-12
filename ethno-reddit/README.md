# Ethno Reddit Experiment

This folder is a fully isolated Reddit-like experiment deployed under `/ethno-reddit`.

## Features

- Fixed user accounts for five participants:
  - `hiro` / `hiro123`
  - `yuxuan` / `yuxuan123`
  - `faria` / `faria123`
  - `aoi` / `aoi123`
  - `leehee` / `leehee123`
- Create/delete subreddits
- Create/delete posts
- Reply/delete replies
- Persistent shared data across sessions/browsers using Netlify Blobs
- AI ethnographer (`gpt-5-nano`) that:
  - updates a visible shared ethnography notebook per subreddit
  - proactively opens interview threads with users
  - asks follow-up questions and closes interviews when enough context is gathered

## Files

- Frontend app: `/ethno-reddit/index.html`, `/ethno-reddit/main.js`, `/ethno-reddit/styles.css`
- Backend API function: `/netlify/functions/ethno-reddit-api.js`
- Netlify routing is namespaced under `/ethno-reddit/api/*`

## Required environment variables (Netlify site settings)

- `OPENAI_API_KEY` = your OpenAI API key
- `ETHNO_REDDIT_AUTH_SECRET` = a random long secret for signing session tokens

## Notes

- This app does not interact with your existing Jekyll pages/posts.
- API endpoints are isolated to `/ethno-reddit/api/*`.
- Change the default account passwords in `netlify/functions/ethno-reddit-api.js` before public use.
