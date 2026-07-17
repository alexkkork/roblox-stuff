chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "download-video") return;

  try {
    const url = new URL(message.url);
    if (!["http:", "https:", "blob:"].includes(url.protocol)) {
      sendResponse({ ok: false, error: "Unsupported video URL." });
      return true;
    }

    if (url.protocol === "blob:") {
      sendResponse({ ok: false, error: "Blob videos cannot be downloaded directly by this helper." });
      return true;
    }

    chrome.downloads.download(
      {
        url: url.toString(),
        filename: cleanFilename(message.filename || "video"),
        saveAs: true
      },
      (downloadId) => {
        const error = chrome.runtime.lastError;
        if (error) sendResponse({ ok: false, error: error.message });
        else sendResponse({ ok: true, downloadId });
      }
    );
  } catch (error) {
    sendResponse({ ok: false, error: String(error && error.message ? error.message : error) });
  }

  return true;
});

function cleanFilename(name) {
  const cleaned = String(name)
    .replace(/[\\/:*?"<>|]+/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 140);
  if (!cleaned) return "video.mp4";
  if (/\.[a-z0-9]{2,5}$/i.test(cleaned)) return cleaned;
  return `${cleaned}.mp4`;
}
