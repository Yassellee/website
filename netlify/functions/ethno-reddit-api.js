const crypto = require("crypto");
const { getStore } = require("@netlify/blobs");

const STATE_KEY = "state";
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7;
const ETHNO_MIN_INTERVAL_MS = 45 * 1000;
const MAX_OPEN_THREADS_PER_USER = 2;
const MAX_RETRIES = 6;

const DEFAULT_USERS = [
  { username: "hiro", password: "hiro123" },
  { username: "yuxuan", password: "yuxuan123" },
  { username: "faria", password: "faria123" },
  { username: "aoi", password: "aoi123" },
  { username: "leehee", password: "leehee123" },
];

function nowIso() {
  return new Date().toISOString();
}

function id(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function normalizeUsername(input) {
  return String(input || "").trim().toLowerCase();
}

function safeText(input, maxLen) {
  const text = String(input || "").trim();
  if (!text) return "";
  return text.slice(0, maxLen);
}

function hmacSecret() {
  return process.env.ETHNO_REDDIT_AUTH_SECRET || process.env.SESSION_SECRET || "ethno-reddit-dev-secret-change-me";
}

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signToken(payloadObj) {
  const payload = b64url(JSON.stringify(payloadObj));
  const sig = crypto.createHmac("sha256", hmacSecret()).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes(".")) return null;
  const [payload, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", hmacSecret()).update(payload).digest("base64url");
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  try {
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (typeof decoded.exp !== "number" || Date.now() / 1000 > decoded.exp) return null;
    return decoded;
  } catch {
    return null;
  }
}

function makePasswordHash(password, saltHex) {
  return crypto.scryptSync(password, Buffer.from(saltHex, "hex"), 64).toString("hex");
}

function verifyPassword(password, saltHex, expectedHash) {
  const hash = makePasswordHash(password, saltHex);
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(expectedHash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function seedState() {
  const createdAt = nowIso();
  return {
    version: 1,
    createdAt,
    users: DEFAULT_USERS.map((u) => {
      const salt = crypto.randomBytes(16).toString("hex");
      return {
        id: id("user"),
        username: u.username,
        passwordSalt: salt,
        passwordHash: makePasswordHash(u.password, salt),
        createdAt,
      };
    }),
    subreddits: [],
    posts: [],
    replies: [],
    threads: [],
    ethnography: [],
    meta: {
      lastEthnographerRunAt: null,
    },
  };
}

async function loadState() {
  const store = getStore("ethno-reddit");
  const existing = await store.get(STATE_KEY, { type: "json" });
  const metadata = await store.getMetadata(STATE_KEY);
  if (existing) {
    return { state: existing, etag: metadata ? metadata.etag : null };
  }

  const seeded = seedState();
  await store.setJSON(STATE_KEY, seeded, { onlyIfNew: true });
  const state = (await store.get(STATE_KEY, { type: "json" })) || seeded;
  const md = await store.getMetadata(STATE_KEY);
  return { state, etag: md ? md.etag : null };
}

async function saveState(state, etag) {
  const store = getStore("ethno-reddit");
  if (etag) {
    const result = await store.setJSON(STATE_KEY, state, { onlyIfMatch: etag });
    if (!result || result.modified === false) {
      const err = new Error("conflict");
      err.code = "CONFLICT";
      throw err;
    }
    return result.etag || null;
  }
  const result = await store.setJSON(STATE_KEY, state);
  return result ? result.etag : null;
}

async function mutateState(mutator) {
  let attempt = 0;
  while (attempt < MAX_RETRIES) {
    attempt += 1;
    const { state, etag } = await loadState();
    const snapshot = JSON.parse(JSON.stringify(state));
    const result = await mutator(snapshot);
    try {
      const newEtag = await saveState(snapshot, etag);
      return { state: snapshot, etag: newEtag, result };
    } catch (err) {
      if (err && err.code === "CONFLICT") continue;
      throw err;
    }
  }
  throw new Error("Failed to persist state due to concurrent writes");
}

function publicState(state, username) {
  return {
    me: { username },
    users: state.users.map((u) => ({ username: u.username })),
    subreddits: state.subreddits,
    posts: state.posts,
    replies: state.replies,
    threads: state.threads.filter((t) => t.username === username),
    ethnography: state.ethnography,
  };
}

function parseAuthUsername(event) {
  const authHeader = event.headers.authorization || event.headers.Authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  const payload = verifyToken(token);
  return payload ? payload.username : null;
}

function json(statusCode, payload) {
  return {
    statusCode,
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(payload),
  };
}

function httpError(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

function parseJsonBody(event) {
  if (!event.body) return {};
  try {
    return JSON.parse(event.body);
  } catch {
    return {};
  }
}

function eventsForSubreddit(state, subredditId) {
  const posts = state.posts
    .filter((p) => p.subredditId === subredditId)
    .map((p) => ({
      type: "post",
      id: p.id,
      author: p.author,
      title: p.title,
      body: p.body,
      createdAt: p.createdAt,
    }));

  const replies = state.replies
    .map((r) => {
      const post = state.posts.find((p) => p.id === r.postId);
      if (!post || post.subredditId !== subredditId) return null;
      return {
        type: "reply",
        id: r.id,
        postId: r.postId,
        author: r.author,
        body: r.body,
        createdAt: r.createdAt,
      };
    })
    .filter(Boolean);

  return [...posts, ...replies].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

function trimArray(arr, max) {
  return Array.isArray(arr) ? arr.slice(0, max) : [];
}

async function callOpenAIJSON({ model, system, user, fallback }) {
  if (!process.env.OPENAI_API_KEY) return fallback;

  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      input: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
      text: { format: { type: "json_object" } },
    }),
  });

  if (!response.ok) {
    return fallback;
  }

  const data = await response.json();
  const raw = data.output_text || "";
  if (!raw) return fallback;

  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

async function updateEthnographyForSubreddit(state, subreddit) {
  const events = eventsForSubreddit(state, subreddit.id);
  if (!events.length) return;

  const recentEvents = events.slice(-35);
  const activeUsers = [...new Set(recentEvents.map((e) => e.author).filter(Boolean))];

  const fallback = {
    summary: `r/${subreddit.name} has ${recentEvents.length} recent contributions from ${activeUsers.length} participants.`,
    patterns: [
      activeUsers.length > 1 ? "Multi-party interaction is present." : "Single-user activity dominates so far.",
    ],
    open_questions: ["What norms should this subreddit encourage?"],
    outreach: activeUsers.slice(0, 2).map((u) => ({ username: u, question: `What motivated your latest contribution in r/${subreddit.name}?` })),
  };

  const modelResult = await callOpenAIJSON({
    model: "gpt-5-nano",
    system:
      "You are an AI ethnographer studying online communities. Return strict JSON with keys: summary (string), patterns (array of strings), open_questions (array of strings), outreach (array of {username, question}). Keep questions non-sensitive and concise.",
    user: JSON.stringify({ subreddit, recentEvents, users: state.users.map((u) => u.username) }),
    fallback,
  });

  const summary = safeText(modelResult.summary, 1200) || fallback.summary;
  const patterns = trimArray(modelResult.patterns, 6).map((x) => safeText(x, 220)).filter(Boolean);
  const openQuestions = trimArray(modelResult.open_questions, 6).map((x) => safeText(x, 220)).filter(Boolean);
  const outreach = trimArray(modelResult.outreach, 4)
    .map((x) => ({ username: normalizeUsername(x.username), question: safeText(x.question, 300) }))
    .filter((x) => x.username && x.question);

  const entry = state.ethnography.find((e) => e.subredditId === subreddit.id);
  if (entry) {
    entry.summary = summary;
    entry.patterns = patterns;
    entry.openQuestions = openQuestions;
    entry.updatedAt = nowIso();
  } else {
    state.ethnography.push({
      subredditId: subreddit.id,
      summary,
      patterns,
      openQuestions,
      updatedAt: nowIso(),
    });
  }

  for (const suggestion of outreach) {
    const username = normalizeUsername(suggestion.username);
    if (!state.users.some((u) => u.username === username)) continue;

    const openThreads = state.threads.filter(
      (t) => t.subredditId === subreddit.id && t.username === username && t.status === "open"
    );
    if (openThreads.length >= MAX_OPEN_THREADS_PER_USER) continue;

    const recentForUser = openThreads.find((t) => t.messages.length && t.messages[t.messages.length - 1].from === "ai");
    if (recentForUser) continue;

    state.threads.push({
      id: id("thread"),
      subredditId: subreddit.id,
      username,
      subject: `Interview on r/${subreddit.name}`,
      status: "open",
      createdAt: nowIso(),
      updatedAt: nowIso(),
      messages: [
        {
          from: "ai",
          body: suggestion.question,
          createdAt: nowIso(),
        },
      ],
    });
  }
}

async function progressThreads(state) {
  const openNeedingFollowup = state.threads.filter((t) => {
    if (t.status !== "open") return false;
    if (!t.messages.length) return false;
    return t.messages[t.messages.length - 1].from === "user";
  });

  for (const thread of openNeedingFollowup) {
    const subreddit = state.subreddits.find((s) => s.id === thread.subredditId);
    if (!subreddit) {
      thread.status = "closed";
      thread.updatedAt = nowIso();
      continue;
    }

    const transcript = thread.messages.slice(-8);
    const fallback = {
      action: transcript.length >= 6 ? "close" : "followup",
      message:
        transcript.length >= 6
          ? "Thank you. I have enough information for now and will keep observing."
          : `Thanks. Could you share one concrete example from r/${subreddit.name}?`,
    };

    const modelResult = await callOpenAIJSON({
      model: "gpt-5-nano",
      system:
        "You are an AI ethnographer interviewer. Return strict JSON with action ('followup' or 'close') and message (string). Ask concise, non-sensitive questions; close when enough context has been gathered.",
      user: JSON.stringify({ subreddit: subreddit.name, username: thread.username, transcript }),
      fallback,
    });

    const action = modelResult.action === "close" ? "close" : "followup";
    const message = safeText(modelResult.message, 350) || fallback.message;

    if (action === "close") {
      thread.messages.push({ from: "ai", body: message, createdAt: nowIso() });
      thread.status = "closed";
      thread.updatedAt = nowIso();
    } else {
      thread.messages.push({ from: "ai", body: message, createdAt: nowIso() });
      thread.updatedAt = nowIso();
    }
  }
}

async function runEthnographer(state, reason) {
  const nowMs = Date.now();
  const last = state.meta.lastEthnographerRunAt ? Date.parse(state.meta.lastEthnographerRunAt) : 0;
  if (reason !== "manual" && nowMs - last < ETHNO_MIN_INTERVAL_MS) {
    return;
  }

  for (const subreddit of state.subreddits) {
    try {
      await updateEthnographyForSubreddit(state, subreddit);
    } catch {
      // Keep core CRUD available even when ethnography refresh fails.
    }
  }
  try {
    await progressThreads(state);
  } catch {
    // Keep core CRUD available even when interview progression fails.
  }
  state.meta.lastEthnographerRunAt = nowIso();
}

async function handleLogin(event) {
  const body = parseJsonBody(event);
  const username = normalizeUsername(body.username);
  const password = String(body.password || "");

  if (!username || !password) return json(400, { error: "Username and password are required" });

  const { state } = await loadState();
  const user = state.users.find((u) => u.username === username);
  if (!user) return json(401, { error: "Invalid credentials" });

  const valid = verifyPassword(password, user.passwordSalt, user.passwordHash);
  if (!valid) return json(401, { error: "Invalid credentials" });

  const token = signToken({ username, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS });
  return json(200, { token, user: { username } });
}

async function requireUser(event) {
  const username = parseAuthUsername(event);
  if (!username) return null;
  const { state } = await loadState();
  if (!state.users.some((u) => u.username === username)) return null;
  return username;
}

function resolveAction(event) {
  const path = event.path || "";
  const publicMarker = "/ethno-reddit/api/";
  const fnMarker = "/.netlify/functions/ethno-reddit-api/";
  if (path.includes(publicMarker)) {
    return path.slice(path.indexOf(publicMarker) + publicMarker.length).split("/")[0];
  }
  if (path.includes(fnMarker)) {
    return path.slice(path.indexOf(fnMarker) + fnMarker.length).split("/")[0];
  }
  return "";
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") {
      return { statusCode: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,DELETE,OPTIONS", "access-control-allow-headers": "content-type,authorization" } };
    }

    const action = resolveAction(event);
    if (!action) return json(404, { error: "Not found" });

    if (action === "login" && event.httpMethod === "POST") {
      return await handleLogin(event);
    }

    const username = await requireUser(event);
    if (!username) return json(401, { error: "Unauthorized" });

    if (action === "bootstrap" && event.httpMethod === "GET") {
      const { state } = await loadState();
      return json(200, publicState(state, username));
    }

    if (action === "subreddits" && event.httpMethod === "POST") {
      const body = parseJsonBody(event);
      const name = normalizeUsername(body.name).replace(/[^a-z0-9_-]/g, "");
      const description = safeText(body.description, 200);
      if (!name) return json(400, { error: "Subreddit name is required" });

      const { state } = await mutateState(async (draft) => {
        if (draft.subreddits.some((s) => s.name === name)) throw httpError(400, "Subreddit already exists");
        draft.subreddits.push({
          id: id("sub"),
          name,
          description,
          createdBy: username,
          createdAt: nowIso(),
        });
        await runEthnographer(draft, "mutation");
      });
      return json(200, publicState(state, username));
    }

    if (action === "subreddits" && event.httpMethod === "DELETE") {
      const body = parseJsonBody(event);
      const subredditId = String(body.subredditId || "");
      if (!subredditId) return json(400, { error: "subredditId is required" });

      const { state } = await mutateState(async (draft) => {
        const exists = draft.subreddits.some((s) => s.id === subredditId);
        if (!exists) throw httpError(404, "Subreddit not found");

        draft.subreddits = draft.subreddits.filter((s) => s.id !== subredditId);
        const postIds = new Set(draft.posts.filter((p) => p.subredditId === subredditId).map((p) => p.id));
        draft.posts = draft.posts.filter((p) => p.subredditId !== subredditId);
        draft.replies = draft.replies.filter((r) => !postIds.has(r.postId));
        draft.ethnography = draft.ethnography.filter((e) => e.subredditId !== subredditId);
        draft.threads = draft.threads.filter((t) => t.subredditId !== subredditId);
        await runEthnographer(draft, "mutation");
      });
      return json(200, publicState(state, username));
    }

    if (action === "posts" && event.httpMethod === "POST") {
      const body = parseJsonBody(event);
      const subredditId = String(body.subredditId || "");
      const title = safeText(body.title, 120);
      const postBody = safeText(body.body, 3000);
      if (!subredditId || !title || !postBody) return json(400, { error: "subredditId, title and body are required" });

      const { state } = await mutateState(async (draft) => {
        if (!draft.subreddits.some((s) => s.id === subredditId)) throw httpError(404, "Subreddit not found");
        draft.posts.push({
          id: id("post"),
          subredditId,
          title,
          body: postBody,
          author: username,
          createdAt: nowIso(),
        });
        await runEthnographer(draft, "mutation");
      });
      return json(200, publicState(state, username));
    }

    if (action === "posts" && event.httpMethod === "DELETE") {
      const body = parseJsonBody(event);
      const postId = String(body.postId || "");
      if (!postId) return json(400, { error: "postId is required" });

      const { state } = await mutateState(async (draft) => {
        const exists = draft.posts.some((p) => p.id === postId);
        if (!exists) throw httpError(404, "Post not found");
        draft.posts = draft.posts.filter((p) => p.id !== postId);
        draft.replies = draft.replies.filter((r) => r.postId !== postId);
        await runEthnographer(draft, "mutation");
      });
      return json(200, publicState(state, username));
    }

    if (action === "replies" && event.httpMethod === "POST") {
      const body = parseJsonBody(event);
      const postId = String(body.postId || "");
      const replyBody = safeText(body.body, 1000);
      if (!postId || !replyBody) return json(400, { error: "postId and body are required" });

      const { state } = await mutateState(async (draft) => {
        if (!draft.posts.some((p) => p.id === postId)) throw httpError(404, "Post not found");
        draft.replies.push({
          id: id("reply"),
          postId,
          body: replyBody,
          author: username,
          createdAt: nowIso(),
        });
        await runEthnographer(draft, "mutation");
      });
      return json(200, publicState(state, username));
    }

    if (action === "replies" && event.httpMethod === "DELETE") {
      const body = parseJsonBody(event);
      const replyId = String(body.replyId || "");
      if (!replyId) return json(400, { error: "replyId is required" });

      const { state } = await mutateState(async (draft) => {
        const exists = draft.replies.some((r) => r.id === replyId);
        if (!exists) throw httpError(404, "Reply not found");
        draft.replies = draft.replies.filter((r) => r.id !== replyId);
        await runEthnographer(draft, "mutation");
      });
      return json(200, publicState(state, username));
    }

    if (action === "thread-reply" && event.httpMethod === "POST") {
      const body = parseJsonBody(event);
      const threadId = String(body.threadId || "");
      const msg = safeText(body.body, 1200);
      if (!threadId || !msg) return json(400, { error: "threadId and body are required" });

      const { state } = await mutateState(async (draft) => {
        const thread = draft.threads.find((t) => t.id === threadId && t.username === username);
        if (!thread) throw httpError(404, "Thread not found");
        if (thread.status !== "open") throw httpError(400, "Thread is closed");
        thread.messages.push({ from: "user", body: msg, createdAt: nowIso() });
        thread.updatedAt = nowIso();
        await runEthnographer(draft, "mutation");
      });
      return json(200, publicState(state, username));
    }

    if (action === "ethnographer-tick" && event.httpMethod === "POST") {
      const body = parseJsonBody(event);
      const source = body.source === "manual" ? "manual" : "heartbeat";
      const { state } = await mutateState(async (draft) => {
        await runEthnographer(draft, source);
      });
      return json(200, publicState(state, username));
    }

    return json(404, { error: "Unknown endpoint" });
  } catch (err) {
    return json(err.statusCode || 500, { error: err.message || "Internal server error" });
  }
};
