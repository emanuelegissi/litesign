"""Keep tests independent of installed desktop utilities and real agents."""
import pytest

import litesign as ls


@pytest.fixture(autouse=True)
def isolate_desktop_tools(monkeypatch):
    original = ls.shutil.which

    def which(name, *args, **kwargs):
        if name in ('systemd-ask-password', 'notify-send'):
            return None
        return original(name, *args, **kwargs)

    monkeypatch.setattr(ls.shutil, 'which', which)
