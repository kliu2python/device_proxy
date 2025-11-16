(function () {
  const params = new URLSearchParams(window.location.search);
  const streamSrc = (params.get('src') || params.get('url') || '').trim();
  const label = (params.get('label') || params.get('title') || '').trim();
  const subtitle = (params.get('subtitle') || params.get('description') || '').trim();
  const streamImage = document.getElementById('embed-stream');
  const streamCanvas = document.getElementById('embed-stream-canvas');
  const placeholder = document.getElementById('embed-placeholder');
  const labelEl = document.getElementById('embed-label');
  const subtitleEl = document.getElementById('embed-subtitle');

  let ws = null;
  let canvasCtx = null;

  function pickFirstValue(values) {
    return values.find((value) => value && value.trim());
  }

  const defaultStream = pickFirstValue([
    document.body.dataset.src,
    document.body.dataset.url,
    document.body.dataset.defaultStream,
    streamImage.dataset.src,
    streamImage.dataset.url,
    streamImage.getAttribute('data-default-stream'),
    document.body.getAttribute('data-default-stream'),
  ]);

  function showPlaceholder(message) {
    if (message) {
      const messageNode = placeholder.querySelector('.embed-placeholder__message');
      if (messageNode) {
        messageNode.textContent = message;
      }
    }
    placeholder.hidden = false;
    streamImage.hidden = true;
    streamCanvas.style.display = 'none';
  }

  function hideAll() {
    placeholder.hidden = true;
    streamImage.hidden = true;
    streamCanvas.style.display = 'none';
  }

  function isWebSocketUrl(url) {
    return url.startsWith('ws://') || url.startsWith('wss://');
  }

  function connectWebSocket(url) {
    hideAll();
    showPlaceholder('Connecting to stream...');

    ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
      console.log('WebSocket connected');
      placeholder.hidden = true;
      streamCanvas.style.display = 'block';
      canvasCtx = streamCanvas.getContext('2d');
    };

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        const blob = new Blob([event.data], { type: 'image/jpeg' });
        const urlCreator = window.URL || window.webkitURL;
        const imageUrl = urlCreator.createObjectURL(blob);

        const img = new Image();
        img.onload = () => {
          if (canvasCtx) {
            // Auto-resize canvas to match image dimensions
            if (streamCanvas.width !== img.width || streamCanvas.height !== img.height) {
              streamCanvas.width = img.width;
              streamCanvas.height = img.height;
            }
            canvasCtx.drawImage(img, 0, 0);
          }
          urlCreator.revokeObjectURL(imageUrl);
        };
        img.src = imageUrl;
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      showPlaceholder('WebSocket connection error. Please check the stream URL.');
    };

    ws.onclose = () => {
      console.log('WebSocket closed');
      showPlaceholder('Stream connection closed.');
    };
  }

  function loadHttpStream(url) {
    hideAll();
    streamImage.src = url;
    streamImage.hidden = false;
    streamImage.addEventListener('error', () => {
      showPlaceholder(
        'We were unable to load the requested stream. Please check that the URL is reachable.'
      );
    });
  }

  if (label) {
    labelEl.textContent = label;
    labelEl.hidden = false;
    document.title = `${label} — Device Stream`;
  }

  if (subtitle) {
    subtitleEl.textContent = subtitle;
    subtitleEl.hidden = false;
  }

  const srcToUse = streamSrc || (defaultStream && defaultStream.trim());

  if (!srcToUse) {
    showPlaceholder('No stream URL was provided.');
  } else if (isWebSocketUrl(srcToUse)) {
    connectWebSocket(srcToUse);
  } else {
    loadHttpStream(srcToUse);
  }

  const closeTriggers = document.querySelectorAll('[data-close]');
  closeTriggers.forEach((trigger) => {
    trigger.addEventListener('click', () => {
      if (ws) {
        ws.close();
      }

      if (window.history.length > 1) {
        window.history.back();
        return;
      }

      if (window.opener) {
        window.close();
        return;
      }

      window.location.replace('about:blank');
    });
  });
})();
