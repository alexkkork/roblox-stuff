const EXT_CLASS = "tiny-video-download-button";
const WRAPPED_ATTR = "data-tiny-video-download-wrapped";
const YOUTUBE_HOSTS = new Set(["youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com"]);

function isYouTube() {
  return YOUTUBE_HOSTS.has(location.hostname);
}

function findVideoUrl(video) {
  if (!video) return "";

  const current = video.currentSrc || video.src || "";
  if (isUsableUrl(current)) return current;

  for (const source of Array.from(video.querySelectorAll("source"))) {
    const url = source.src || source.getAttribute("src") || "";
    if (isUsableUrl(url)) return url;
  }

  return "";
}

function isUsableUrl(url) {
  if (!url) return false;
  try {
    const parsed = new URL(url, location.href);
    if (!["http:", "https:", "blob:"].includes(parsed.protocol)) return false;
    return true;
  } catch {
    return false;
  }
}

function filenameFor(video, url) {
  const title = document.title || "video";
  try {
    const parsed = new URL(url, location.href);
    const pathName = parsed.pathname.split("/").filter(Boolean).pop() || "";
    if (/\.[a-z0-9]{2,5}$/i.test(pathName)) return pathName;
  } catch {}

  const type = video.currentSrc ? "" : video.type || "";
  const ext = type.includes("webm") ? ".webm" : type.includes("ogg") ? ".ogv" : ".mp4";
  return `${title}${ext}`;
}

function showToast(text) {
  let toast = document.querySelector(".tiny-video-download-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.className = "tiny-video-download-toast";
    document.documentElement.appendChild(toast);
  }
  toast.textContent = text;
  toast.classList.add("visible");
  setTimeout(() => toast.classList.remove("visible"), 2600);
}

function attach(video) {
  if (!(video instanceof HTMLVideoElement)) return;
  if (video.getAttribute(WRAPPED_ATTR)) return;
  if (video.offsetWidth < 160 || video.offsetHeight < 90) return;

  video.setAttribute(WRAPPED_ATTR, "1");

  const button = document.createElement("button");
  button.type = "button";
  button.className = EXT_CLASS;
  button.textContent = "DL";
  button.title = isYouTube()
    ? "YouTube downloads are handled by YouTube's official options."
    : "Download this direct video file";

  button.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();

    if (isYouTube()) {
      showToast("YouTube stream extraction is not supported. Use YouTube's official download or Studio export options.");
      return;
    }

    const url = findVideoUrl(video);
    if (!url) {
      showToast("No direct video URL found.");
      return;
    }

    if (url.startsWith("blob:")) {
      showToast("This page uses a blob/stream URL. Direct download is not available.");
      return;
    }

    chrome.runtime.sendMessage(
      {
        type: "download-video",
        url: new URL(url, location.href).toString(),
        filename: filenameFor(video, url)
      },
      (response) => {
        if (!response || !response.ok) {
          showToast(response && response.error ? response.error : "Download failed.");
        }
      }
    );
  }, true);

  const parent = video.parentElement || document.body;
  const parentStyle = getComputedStyle(parent);
  if (parentStyle.position === "static") parent.style.position = "relative";
  parent.appendChild(button);
}

function scan() {
  for (const video of document.querySelectorAll("video")) attach(video);
}

const observer = new MutationObserver(() => scan());
observer.observe(document.documentElement, { childList: true, subtree: true });
scan();
setInterval(scan, 1500);
