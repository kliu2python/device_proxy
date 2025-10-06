"""Client helpers for interacting with the proxy server.

This module exposes a small factory that mirrors ``webdriver.Remote`` so that
existing projects that already expect to receive a Selenium/Appium WebDriver
instance can use the proxy server transparently.  The function simply delegates
to :class:`appium.webdriver.webdriver.WebDriver` after normalising the proxy
URL and preparing the desired capabilities/options payload.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

try:
    from appium import webdriver as appium_webdriver
    from appium.options.common import AppiumOptions
except ImportError as exc:  # pragma: no cover - defensive import guard
    raise ImportError(
        "The Appium Python client is required to create proxy WebDriver instances."
    ) from exc


def create_proxy_webdriver(
    proxy_server: str,
    desired_capabilities: Optional[Dict[str, Any]] = None,
    *,
    options: Optional[AppiumOptions] = None,
    keep_alive: bool = True,
    **remote_kwargs: Any,
) -> appium_webdriver.Remote:
    """Return a ``webdriver.Remote`` instance targeting the proxy server.

    Parameters
    ----------
    proxy_server:
        Base URL of the proxy server.  If the ``/wd/hub`` suffix is omitted it
        will be appended automatically.
    desired_capabilities:
        Legacy capabilities dictionary.  When provided ``AppiumOptions`` will be
        created internally and populated with these capabilities.
    options:
        Optional :class:`AppiumOptions` instance.  When omitted a new instance is
        created from ``desired_capabilities``.  Passing both is allowed; the
        capabilities dictionary will be merged into a copy of the provided
        options object to avoid mutating it.
    keep_alive:
        Whether to enable HTTP keep-alive on the remote session.  Defaults to
        ``True`` to mirror Selenium/Appium's default behaviour.
    **remote_kwargs:
        Additional keyword arguments forwarded to ``webdriver.Remote`` (e.g.
        ``direct_connection`` or ``timeout``).

    Returns
    -------
    appium.webdriver.webdriver.WebDriver
        A WebDriver instance backed by the proxy server.
    """

    if options is None:
        if desired_capabilities is None:
            raise ValueError(
                "Either 'desired_capabilities' or 'options' must be provided to create a WebDriver."
            )
        options = AppiumOptions()
    else:
        options = options.copy()

    if desired_capabilities:
        options.load_capabilities(desired_capabilities)

    executor = proxy_server.rstrip("/")
    if not executor.endswith("/wd/hub"):
        executor = f"{executor}/wd/hub"

    return appium_webdriver.Remote(
        command_executor=executor,
        options=options,
        keep_alive=keep_alive,
        **remote_kwargs,
    )


__all__ = ["create_proxy_webdriver"]
