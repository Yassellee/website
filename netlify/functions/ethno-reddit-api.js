const crypto = require("crypto");
const { getStore } = require("@netlify/blobs");

const STATE_KEY = "state";
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7;
const HEARTBEAT_INTERVAL_MS = 45 * 1000;
const MAX_OPEN_THREADS_PER_USER = 2;
const MAX_RETRIES = 6;
const MAX_EVENT_LOG = 800;
const MAX_OBSERVATIONS = 120;

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

function trimArray(arr, max, maxItemLen = 240) {
  return Array.isArray(arr)
    ? arr
        .slice(0, max)
        .map((x) => safeText(x, maxItemLen))
        .filter(Boolean)
    : [];
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

function seedState() {
  const createdAt = nowIso();
  return {
    version: 2,
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
    eventLog: [],
    meta: {
      lastEthnographerRunAt: null,
      processedEventCount: 0,
    },
  };
}

function migrateState(state) {
  if (!Array.isArray(state.eventLog)) state.eventLog = [];
  if (!state.meta) state.meta = {};
  if (typeof state.meta.processedEventCount !== "number") state.meta.processedEventCount = 0;
  if (!Array.isArray(state.ethnography)) state.ethnography = [];

  for (const entry of state.ethnography) {
    if (!Array.isArray(entry.observations)) entry.observations = [];
    if (!Array.isArray(entry.patterns)) entry.patterns = [];
    if (!Array.isArray(entry.openQuestions)) entry.openQuestions = [];
    if (!entry.updatedAt) entry.updatedAt = nowIso();
    if (!entry.summary) entry.summary = "No summary yet.";
  }

  state.version = 2;
  return state;
}

async function loadState() {
  const store = getStore("ethno-reddit");
  const existing = await store.get(STATE_KEY, { type: "json" });
  const metadata = await store.getMetadata(STATE_KEY);

  if (existing) {
    return { state: migrateState(existing), etag: metadata ? metadata.etag : null };
  }

  const seeded = seedState();
  await store.setJSON(STATE_KEY, seeded, { onlyIfNew: true });
  const state = (await store.get(STATE_KEY, { type: "json" })) || seeded;
  const md = await store.getMetadata(STATE_KEY);
  return { state: migrateState(state), etag: md ? md.etag : null };
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
    const draft = JSON.parse(JSON.stringify(state));
    const result = await mutator(draft);
    try {
      const newEtag = await saveState(draft, etag);
      return { state: draft, etag: newEtag, result };
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
  if (path.includes(publicMarker)) return path.slice(path.indexOf(publicMarker) + publicMarker.length).split("/")[0];
  if (path.includes(fnMarker)) return path.slice(path.indexOf(fnMarker) + fnMarker.length).split("/")[0];
  return "";
}

function ensureEthnographyEntry(state, subredditId, subredditName) {
  let entry = state.ethnography.find((e) => e.subredditId === subredditId);
  if (!entry) {
    entry = {
      subredditId,
      summary: `r/${subredditName} has no activity yet.`,
      patterns: [],
      openQuestions: [],
      observations: [],
      updatedAt: nowIso(),
    };
    state.ethnography.push(entry);
  }
  if (!Array.isArray(entry.observations)) entry.observations = [];
  return entry;
}

function addObservation(entry, observation) {
  entry.observations.push(observation);
  if (entry.observations.length > MAX_OBSERVATIONS) {
    entry.observations = entry.observations.slice(-MAX_OBSERVATIONS);
  }
}

function addEvent(state, event) {
  const normalized = {
    id: id("evt"),
    createdAt: nowIso(),
    subredditId: event.subredditId || null,
    actor: normalizeUsername(event.actor || "system"),
    type: event.type,
    postId: event.postId || null,
    payload: event.payload || {},
  };
  state.eventLog.push(normalized);
  while (state.eventLog.length > MAX_EVENT_LOG) {
    state.eventLog.shift();
    state.meta.processedEventCount = Math.max(0, state.meta.processedEventCount - 1);
  }
  return normalized;
}

function addPassiveObservationFromEvent(state, evt) {
  if (!evt.subredditId) return;
  const subreddit = state.subreddits.find((s) => s.id === evt.subredditId);
  if (!subreddit) return;
  const entry = ensureEthnographyEntry(state, subreddit.id, subreddit.name);

  let body = "";
  if (evt.type === "post_created") {
    body = `${evt.actor} created a post titled "${safeText(evt.payload.title, 80)}".`;
  } else if (evt.type === "reply_created") {
    body = `${evt.actor} replied in r/${subreddit.name}.`;
  } else if (evt.type === "interview_reply") {
    body = `${evt.actor} responded to an ethnography interview thread.`;
  } else if (evt.type === "subreddit_created") {
    body = `${evt.actor} created this subreddit.`;
  }

  if (!body) return;
  addObservation(entry, {
    id: id("obs"),
    kind: "passive",
    sourceEventId: evt.id,
    createdAt: nowIso(),
    body,
  });
  entry.updatedAt = nowIso();
}

function eventsForSubreddit(state, subredditId) {
  return state.eventLog
    .filter((e) => e.subredditId === subredditId)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

function userActivity(events) {
  const counts = {};
  for (const e of events) {
    if (!e.actor || e.actor === "system") continue;
    counts[e.actor] = (counts[e.actor] || 0) + 1;
  }
  return counts;
}

async function callOpenAIJSON({ model, system, user, fallback }) {
  if (!process.env.OPENAI_API_KEY) return fallback;

  try {
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

    if (!response.ok) return fallback;
    const data = await response.json();
    const raw = data.output_text || "";
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function maybeOpenInterviewThread(state, subreddit, username, question) {
  const user = normalizeUsername(username);
  if (!state.users.some((u) => u.username === user)) return;

  const openThreads = state.threads.filter(
    (t) => t.subredditId === subreddit.id && t.username === user && t.status === "open"
  );
  if (openThreads.length >= MAX_OPEN_THREADS_PER_USER) return;

  const hasRecentUnansweredAi = openThreads.some((t) => {
    if (!t.messages.length) return false;
    return t.messages[t.messages.length - 1].from === "ai";
  });
  if (hasRecentUnansweredAi) return;

  state.threads.push({
    id: id("thread"),
    subredditId: subreddit.id,
    username: user,
    subject: `Interview on r/${subreddit.name}`,
    status: "open",
    createdAt: nowIso(),
    updatedAt: nowIso(),
    messages: [{ from: "ai", body: safeText(question, 350), createdAt: nowIso() }],
  });
}

async function activeSubredditAnalysis(state, subreddit, newEvents) {
  const entry = ensureEthnographyEntry(state, subreddit.id, subreddit.name);
  const allEvents = eventsForSubreddit(state, subreddit.id).slice(-50);
  const activity = userActivity(allEvents);
  const activeUsers = Object.keys(activity);

  const fallback = {
    summary: `r/${subreddit.name} has ${allEvents.length} logged events. Active participants: ${activeUsers.join(", ") || "none"}.`,
    patterns: activeUsers.length > 1 ? ["Conversation is multi-participant."] : ["Most activity is from one participant."],
    open_questions: ["What shared norm should members adopt in this subreddit?"],
    field_notes: [
      newEvents.length
        ? `Observed ${newEvents.length} new events since last ethnography pass.`
        : "No new events since the last pass.",
    ],
    outreach: activeUsers.slice(0, 2).map((u) => ({ username: u, question: `What stood out to you in recent activity on r/${subreddit.name}?` })),
  };

  const model = await callOpenAIJSON({
    model: "gpt-5-nano",
    system:
      "You are an AI ethnographer for an online forum. Return strict JSON with keys: summary (string), patterns (array of strings), open_questions (array), field_notes (array), outreach (array of {username, question}). Keep notes concrete, non-sensitive, and tied to observed behavior.",
    user: JSON.stringify({
      subreddit,
      recentEvents: allEvents,
      deltaEvents: newEvents,
      activeUsers,
      existingOpenQuestions: entry.openQuestions,
    }),
    fallback,
  });

  entry.summary = safeText(model.summary, 1300) || fallback.summary;
  entry.patterns = trimArray(model.patterns, 8, 260);
  entry.openQuestions = trimArray(model.open_questions, 8, 260);
  entry.updatedAt = nowIso();

  for (const note of trimArray(model.field_notes, 6, 320)) {
    addObservation(entry, {
      id: id("obs"),
      kind: "active",
      sourceEventId: null,
      createdAt: nowIso(),
      body: note,
    });
  }

  const outreach = Array.isArray(model.outreach) ? model.outreach.slice(0, 4) : [];
  for (const target of outreach) {
    const username = normalizeUsername(target && target.username);
    const question = safeText(target && target.question, 320);
    if (!username || !question) continue;
    maybeOpenInterviewThread(state, subreddit, username, question);
  }
}

async function progressThreads(state) {
  const candidates = state.threads.filter((t) => {
    if (t.status !== "open") return false;
    if (!t.messages.length) return false;
    return t.messages[t.messages.length - 1].from === "user";
  });

  for (const thread of candidates) {
    const subreddit = state.subreddits.find((s) => s.id === thread.subredditId);
    if (!subreddit) {
      thread.status = "closed";
      thread.updatedAt = nowIso();
      continue;
    }

    const transcript = thread.messages.slice(-10);
    const fallback = {
      action: transcript.length >= 8 ? "close" : "followup",
      message:
        transcript.length >= 8
          ? "Thanks. I have enough context for now and will continue observing the subreddit."
          : `Thanks. Can you give one specific example from r/${subreddit.name} that influenced your view?`,
    };

    const model = await callOpenAIJSON({
      model: "gpt-5-nano",
      system:
        "You are an ethnography interviewer. Return strict JSON with action ('followup' or 'close') and message (string). Ask concise non-sensitive questions and close gracefully when enough context is gathered.",
      user: JSON.stringify({ subreddit: subreddit.name, username: thread.username, transcript }),
      fallback,
    });

    const action = model.action === "close" ? "close" : "followup";
    const message = safeText(model.message, 350) || fallback.message;
    thread.messages.push({ from: "ai", body: message, createdAt: nowIso() });
    thread.updatedAt = nowIso();
    if (action === "close") thread.status = "closed";
  }
}

async function runEthnographer(state, reason) {
  const nowMs = Date.now();
  const last = state.meta.lastEthnographerRunAt ? Date.parse(state.meta.lastEthnographerRunAt) : 0;

  if (reason === "heartbeat" && nowMs - last < HEARTBEAT_INTERVAL_MS) {
    return;
  }

  const processed = Math.max(0, Math.min(state.meta.processedEventCount || 0, state.eventLog.length));
  const newEvents = state.eventLog.slice(processed);

  const targetSubredditIds = new Set();
  for (const evt of newEvents) {
    if (evt.subredditId) targetSubredditIds.add(evt.subredditId);
  }
  if (reason === "manual" || reason === "heartbeat") {
    for (const sub of state.subreddits) targetSubredditIds.add(sub.id);
  }

  for (const subredditId of targetSubredditIds) {
    const subreddit = state.subreddits.find((s) => s.id === subredditId);
    if (!subreddit) continue;
    const delta = newEvents.filter((e) => e.subredditId === subredditId);
    try {
      await activeSubredditAnalysis(state, subreddit, delta);
    } catch {
      // Keep product operations working even when active analysis fails.
    }
  }

  try {
    await progressThreads(state);
  } catch {
    // Keep product operations working even when thread progression fails.
  }

  state.meta.processedEventCount = state.eventLog.length;
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

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") {
      return {
        statusCode: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
          "access-control-allow-headers": "content-type,authorization",
        },
      };
    }

    const action = resolveAction(event);
    if (!action) return json(404, { error: "Not found" });

    if (action === "login" && event.httpMethod === "POST") {
      return handleLogin(event);
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

        const subreddit = {
          id: id("sub"),
          name,
          description,
          createdBy: username,
          createdAt: nowIso(),
        };
        draft.subreddits.push(subreddit);
        ensureEthnographyEntry(draft, subreddit.id, subreddit.name);

        const evt = addEvent(draft, {
          subredditId: subreddit.id,
          actor: username,
          type: "subreddit_created",
          payload: { name: subreddit.name },
        });
        addPassiveObservationFromEvent(draft, evt);
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
        draft.eventLog = draft.eventLog.filter((e) => e.subredditId !== subredditId);
        draft.meta.processedEventCount = Math.min(draft.meta.processedEventCount, draft.eventLog.length);
      });

      return json(200, publicState(state, username));
    }

    if (action === "posts" && event.httpMethod === "POST") {
      const body = parseJsonBody(event);
      const subredditId = String(body.subredditId || "");
      const title = safeText(body.title, 120);
      const postBody = safeText(body.body, 3000);
      if (!subredditId || !title || !postBody) {
        return json(400, { error: "subredditId, title and body are required" });
      }

      const { state } = await mutateState(async (draft) => {
        if (!draft.subreddits.some((s) => s.id === subredditId)) throw httpError(404, "Subreddit not found");

        const post = {
          id: id("post"),
          subredditId,
          title,
          body: postBody,
          author: username,
          createdAt: nowIso(),
        };
        draft.posts.push(post);

        const evt = addEvent(draft, {
          subredditId,
          actor: username,
          type: "post_created",
          postId: post.id,
          payload: { title: post.title },
        });
        addPassiveObservationFromEvent(draft, evt);

        await runEthnographer(draft, "mutation");
      });

      return json(200, publicState(state, username));
    }

    if (action === "posts" && event.httpMethod === "DELETE") {
      const body = parseJsonBody(event);
      const postId = String(body.postId || "");
      if (!postId) return json(400, { error: "postId is required" });

      const { state } = await mutateState(async (draft) => {
        const post = draft.posts.find((p) => p.id === postId);
        if (!post) throw httpError(404, "Post not found");

        draft.posts = draft.posts.filter((p) => p.id !== postId);
        draft.replies = draft.replies.filter((r) => r.postId !== postId);

        addEvent(draft, {
          subredditId: post.subredditId,
          actor: username,
          type: "post_deleted",
          postId,
          payload: { title: post.title },
        });
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
        const post = draft.posts.find((p) => p.id === postId);
        if (!post) throw httpError(404, "Post not found");

        const reply = {
          id: id("reply"),
          postId,
          body: replyBody,
          author: username,
          createdAt: nowIso(),
        };
        draft.replies.push(reply);

        const evt = addEvent(draft, {
          subredditId: post.subredditId,
          actor: username,
          type: "reply_created",
          postId,
          payload: { body: safeText(replyBody, 120) },
        });
        addPassiveObservationFromEvent(draft, evt);

        await runEthnographer(draft, "mutation");
      });

      return json(200, publicState(state, username));
    }

    if (action === "replies" && event.httpMethod === "DELETE") {
      const body = parseJsonBody(event);
      const replyId = String(body.replyId || "");
      if (!replyId) return json(400, { error: "replyId is required" });

      const { state } = await mutateState(async (draft) => {
        const reply = draft.replies.find((r) => r.id === replyId);
        if (!reply) throw httpError(404, "Reply not found");

        const post = draft.posts.find((p) => p.id === reply.postId);
        draft.replies = draft.replies.filter((r) => r.id !== replyId);

        if (post) {
          addEvent(draft, {
            subredditId: post.subredditId,
            actor: username,
            type: "reply_deleted",
            postId: post.id,
            payload: {},
          });
        }
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

        const evt = addEvent(draft, {
          subredditId: thread.subredditId,
          actor: username,
          type: "interview_reply",
          payload: { body: safeText(msg, 120) },
        });
        addPassiveObservationFromEvent(draft, evt);

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
