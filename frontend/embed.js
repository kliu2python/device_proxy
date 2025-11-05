(function () {
  const params = new URLSearchParams(window.location.search);
  const streamSrc = (params.get('src') || params.get('url') || '').trim();
  const label = (params.get('label') || params.get('title') || '').trim();
  const subtitle = (params.get('subtitle') || params.get('description') || '').trim();
  const streamImage = document.getElementById('embed-stream');
  const placeholder = document.getElementById('embed-placeholder');
  const labelEl = document.getElementById('embed-label');
  const subtitleEl = document.getElementById('embed-subtitle');

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
        messageNode.innerHTML = message;
      }
    }
    placeholder.hidden = false;
    streamImage.hidden = true;
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
  } else {
    streamImage.src = srcToUse;
    streamImage.hidden = false;
    streamImage.addEventListener('error', () => {
      showPlaceholder(
        'We were unable to load the requested stream. Please check that the URL is reachable.'
      );
    });
  }

  const closeTriggers = document.querySelectorAll('[data-close]');
  closeTriggers.forEach((trigger) => {
    trigger.addEventListener('click', () => {
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
