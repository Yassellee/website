const API_BASE = "/ethno-reddit/api";
const tokenKey = "ethno_reddit_token";

const state = {
  token: localStorage.getItem(tokenKey) || "",
  me: null,
  users: [],
  subreddits: [],
  posts: [],
  replies: [],
  threads: [],
  ethnography: [],
  selectedSubredditId: null,
};

const el = {
  authPanel: document.getElementById("auth-panel"),
  app: document.getElementById("app"),
  loginForm: document.getElementById("login-form"),
  loginError: document.getElementById("login-error"),
  username: document.getElementById("username"),
  password: document.getElementById("password"),
  sessionBox: document.getElementById("session-box"),
  subredditForm: document.getElementById("subreddit-form"),
  subredditName: document.getElementById("subreddit-name"),
  subredditDescription: document.getElementById("subreddit-description"),
  subredditList: document.getElementById("subreddit-list"),
  currentSubredditLabel: document.getElementById("current-subreddit-label"),
  deleteSubredditBtn: document.getElementById("delete-subreddit-btn"),
  postForm: document.getElementById("post-form"),
  postTitle: document.getElementById("post-title"),
  postBody: document.getElementById("post-body"),
  postList: document.getElementById("post-list"),
  ethnographyView: document.getElementById("ethnography-view"),
  inbox: document.getElementById("inbox"),
  manualAiBtn: document.getElementById("manual-ai-btn"),
  postTemplate: document.getElementById("post-template"),
};

function usernameDisplay(name) {
  return name.charAt(0).toUpperCase() + name.slice(1);
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;

  const res = await fetch(`${API_BASE}/${path}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function logout() {
  state.token = "";
  state.me = null;
  localStorage.removeItem(tokenKey);
  render();
}

function setFromBootstrap(data) {
  state.me = data.me;
  state.users = data.users;
  state.subreddits = data.subreddits;
  state.posts = data.posts;
  state.replies = data.replies;
  state.threads = data.threads;
  state.ethnography = data.ethnography;

  if (state.selectedSubredditId && !state.subreddits.some((s) => s.id === state.selectedSubredditId)) {
    state.selectedSubredditId = null;
  }
  if (!state.selectedSubredditId && state.subreddits.length) {
    state.selectedSubredditId = state.subreddits[0].id;
  }
}

async function refreshData() {
  const data = await api("bootstrap", { method: "GET" });
  setFromBootstrap(data);
  render();
}

function triggerEthnographerAsync() {
  api("ethnographer-tick", { method: "POST", body: JSON.stringify({ source: "heartbeat" }) })
    .then(() => refreshData())
    .catch(() => {});
}

async function maybeAuthRestore() {
  if (!state.token) {
    render();
    return;
  }
  try {
    await refreshData();
  } catch {
    logout();
  }
}

function getSelectedSubreddit() {
  return state.subreddits.find((s) => s.id === state.selectedSubredditId) || null;
}

function renderSession() {
  if (!state.me) {
    el.sessionBox.textContent = "Not signed in";
    return;
  }
  el.sessionBox.innerHTML = `Signed in as <strong>${usernameDisplay(state.me.username)}</strong> <button id="logout-btn">Logout</button>`;
  document.getElementById("logout-btn").onclick = logout;
}

function renderSubreddits() {
  el.subredditList.innerHTML = "";
  state.subreddits.forEach((sub) => {
    const li = document.createElement("li");
    li.className = sub.id === state.selectedSubredditId ? "active" : "";
    li.innerHTML = `<strong>r/${escapeHtml(sub.name)}</strong><div class="muted">${escapeHtml(sub.description || "No description")}</div>`;
    li.onclick = () => {
      state.selectedSubredditId = sub.id;
      render();
    };
    el.subredditList.appendChild(li);
  });
}

function renderPosts() {
  const selected = getSelectedSubreddit();
  el.postList.innerHTML = "";

  if (!selected) {
    el.currentSubredditLabel.textContent = "Posts";
    el.postForm.classList.add("hidden");
    el.deleteSubredditBtn.classList.add("hidden");
    el.postList.innerHTML = `<p class="muted">Create a subreddit to start posting.</p>`;
    return;
  }

  el.currentSubredditLabel.textContent = `Posts in r/${selected.name}`;
  el.postForm.classList.remove("hidden");
  el.deleteSubredditBtn.classList.remove("hidden");

  const posts = state.posts.filter((p) => p.subredditId === selected.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  if (!posts.length) {
    el.postList.innerHTML = `<p class="muted">No posts yet.</p>`;
    return;
  }

  posts.forEach((post) => {
    const node = el.postTemplate.content.cloneNode(true);
    node.querySelector(".post-title").textContent = post.title;
    node.querySelector(".meta").textContent = `by ${usernameDisplay(post.author)} at ${new Date(post.createdAt).toLocaleString()}`;
    node.querySelector(".post-body").textContent = post.body;

    const delBtn = node.querySelector(".delete-post");
    delBtn.onclick = async () => {
      if (!confirm("Delete this post and all replies?")) return;
      await api("posts", {
        method: "DELETE",
        body: JSON.stringify({ postId: post.id }),
      });
      await refreshData();
      triggerEthnographerAsync();
    };

    const repliesContainer = node.querySelector(".replies");
    const replies = state.replies.filter((r) => r.postId === post.id).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    replies.forEach((reply) => {
      const item = document.createElement("div");
      item.className = "reply-item";
      item.innerHTML = `<div class="row-between"><span class="muted">${escapeHtml(usernameDisplay(reply.author))} · ${new Date(reply.createdAt).toLocaleString()}</span><button class="danger">Delete</button></div><p>${escapeHtml(reply.body)}</p>`;
      item.querySelector("button").onclick = async () => {
        if (!confirm("Delete this reply?")) return;
        await api("replies", {
          method: "DELETE",
          body: JSON.stringify({ replyId: reply.id }),
        });
        await refreshData();
        triggerEthnographerAsync();
      };
      repliesContainer.appendChild(item);
    });

    const replyForm = node.querySelector(".reply-form");
    replyForm.onsubmit = async (e) => {
      e.preventDefault();
      const textarea = replyForm.querySelector("textarea");
      const body = textarea.value.trim();
      if (!body) return;
      await api("replies", {
        method: "POST",
        body: JSON.stringify({ postId: post.id, body }),
      });
      textarea.value = "";
      await refreshData();
      triggerEthnographerAsync();
    };

    el.postList.appendChild(node);
  });
}

function renderEthnography() {
  const selected = getSelectedSubreddit();
  el.ethnographyView.innerHTML = "";
  if (!selected) {
    el.ethnographyView.innerHTML = `<p class="muted">No subreddit selected.</p>`;
    return;
  }
  const entry = state.ethnography.find((x) => x.subredditId === selected.id);
  if (!entry) {
    el.ethnographyView.innerHTML = `<p class="muted">No notes yet. The AI ethnographer will update this notebook as activity appears.</p>`;
    return;
  }

  const patterns = (entry.patterns || []).map((p) => `<li>${escapeHtml(p)}</li>`).join("");
  const questions = (entry.openQuestions || []).map((q) => `<li>${escapeHtml(q)}</li>`).join("");
  const observations = (entry.observations || [])
    .slice()
    .sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""))
    .slice(0, 12)
    .map(
      (o) =>
        `<li><span class="muted">[${escapeHtml(o.kind || "note")}] ${new Date(o.createdAt).toLocaleString()}</span><div>${escapeHtml(o.body || "")}</div></li>`
    )
    .join("");
  el.ethnographyView.innerHTML = `
    <p><strong>Last update:</strong> ${new Date(entry.updatedAt).toLocaleString()}</p>
    <p>${escapeHtml(entry.summary || "No summary.")}</p>
    <div>
      <strong>Patterns</strong>
      <ul>${patterns || "<li>None yet.</li>"}</ul>
    </div>
    <div>
      <strong>Open questions</strong>
      <ul>${questions || "<li>None right now.</li>"}</ul>
    </div>
    <div>
      <strong>Observation Log</strong>
      <ul>${observations || "<li>No observations yet.</li>"}</ul>
    </div>
  `;
}

function renderInbox() {
  el.inbox.innerHTML = "";
  const myThreads = state.threads
    .filter((t) => t.username === state.me.username)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));

  if (!myThreads.length) {
    el.inbox.innerHTML = `<p class="muted">No interview messages yet.</p>`;
    return;
  }

  myThreads.forEach((thread) => {
    const selected = state.subreddits.find((s) => s.id === thread.subredditId);
    const wrapper = document.createElement("article");
    wrapper.className = "thread stack";

    const log = thread.messages
      .map((m) => `<div class="${m.from === "ai" ? "bubble-ai" : "bubble-user"}"><strong>${m.from.toUpperCase()}</strong>: ${escapeHtml(m.body)}</div>`)
      .join("");

    wrapper.innerHTML = `
      <div class="row-between">
        <strong>${escapeHtml(thread.subject || "Interview")}</strong>
        <span class="muted">${escapeHtml(thread.status)}</span>
      </div>
      <p class="muted">r/${escapeHtml(selected ? selected.name : "unknown")} · Updated ${new Date(thread.updatedAt).toLocaleString()}</p>
      <div class="stack">${log}</div>
    `;

    if (thread.status === "open") {
      const form = document.createElement("form");
      form.className = "stack";
      form.innerHTML = `
        <textarea rows="2" maxlength="1200" placeholder="Reply to AI ethnographer" required></textarea>
        <button type="submit">Send reply</button>
      `;
      form.onsubmit = async (e) => {
        e.preventDefault();
        const text = form.querySelector("textarea").value.trim();
        if (!text) return;
        await api("thread-reply", {
          method: "POST",
          body: JSON.stringify({ threadId: thread.id, body: text }),
        });
        await refreshData();
        triggerEthnographerAsync();
      };
      wrapper.appendChild(form);
    }

    el.inbox.appendChild(wrapper);
  });
}

function render() {
  renderSession();
  if (!state.me) {
    el.authPanel.classList.remove("hidden");
    el.app.classList.add("hidden");
    return;
  }
  el.authPanel.classList.add("hidden");
  el.app.classList.remove("hidden");
  renderSubreddits();
  renderPosts();
  renderEthnography();
  renderInbox();
}

el.loginForm.onsubmit = async (e) => {
  e.preventDefault();
  el.loginError.textContent = "";
  try {
    const data = await api("login", {
      method: "POST",
      body: JSON.stringify({
        username: el.username.value.trim(),
        password: el.password.value,
      }),
    });
    state.token = data.token;
    localStorage.setItem(tokenKey, state.token);
    await refreshData();
    el.password.value = "";
  } catch (err) {
    el.loginError.textContent = err.message;
  }
};

el.subredditForm.onsubmit = async (e) => {
  e.preventDefault();
  await api("subreddits", {
    method: "POST",
    body: JSON.stringify({
      name: el.subredditName.value.trim(),
      description: el.subredditDescription.value.trim(),
    }),
  });
  el.subredditName.value = "";
  el.subredditDescription.value = "";
  await refreshData();
  triggerEthnographerAsync();
};

el.deleteSubredditBtn.onclick = async () => {
  const sub = getSelectedSubreddit();
  if (!sub) return;
  if (!confirm(`Delete r/${sub.name} and all posts, replies, and ethnography notes?`)) return;
  await api("subreddits", {
    method: "DELETE",
    body: JSON.stringify({ subredditId: sub.id }),
  });
  await refreshData();
  triggerEthnographerAsync();
};

el.postForm.onsubmit = async (e) => {
  e.preventDefault();
  const sub = getSelectedSubreddit();
  if (!sub) return;
  await api("posts", {
    method: "POST",
    body: JSON.stringify({
      subredditId: sub.id,
      title: el.postTitle.value.trim(),
      body: el.postBody.value.trim(),
    }),
  });
  el.postTitle.value = "";
  el.postBody.value = "";
  await refreshData();
  triggerEthnographerAsync();
};

el.manualAiBtn.onclick = async () => {
  await api("ethnographer-tick", { method: "POST", body: JSON.stringify({ source: "manual" }) });
  await refreshData();
};

setInterval(() => {
  if (!state.me) return;
  api("ethnographer-tick", { method: "POST", body: JSON.stringify({ source: "heartbeat" }) })
    .then(() => refreshData())
    .catch(() => {});
}, 60000);

maybeAuthRestore();
