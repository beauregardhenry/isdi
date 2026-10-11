"""Four-word client IDs and each installation's own word list (from Sherloc)."""

import re

import pytest

from isdi import clientwords


def test_the_word_list_is_large_and_clean():
    words = clientwords.WORDS
    assert len(words) >= 2900
    assert len(set(words)) == len(words)
    assert all(re.fullmatch(r"[a-z]{3,9}", w) for w in words)


# Words that must never appear in an ID someone else might see on a screen or
# a piece of paper. Not exhaustive; it guards against careless additions.
NEVER = {
    "abuse",
    "spy",
    "track",
    "stalk",
    "watch",
    "monitor",
    "camera",
    "gun",
    "knife",
    "rope",
    "chain",
    "kill",
    "dead",
    "blood",
    "hurt",
    "fear",
    "trap",
    "cage",
    "lock",
    "hammer",
    "arrow",
    "wolf",
    "drug",
    "beer",
    "wine",
    "date",
    "kiss",
    "naked",
    "police",
    "court",
    "jail",
    "victim",
    "escape",
}


def test_the_word_list_avoids_alarming_words():
    assert NEVER.isdisjoint(clientwords.WORDS)


def test_an_id_is_four_different_words_from_the_pool():
    pool = clientwords.WORDS[:50]
    for _ in range(50):
        words = clientwords.make_client_id(pool=pool).split("-")
        assert len(words) == 4 == len(set(words)) and set(words) <= set(pool)


def test_ids_differ():
    assert len({clientwords.make_client_id() for _ in range(200)}) == 200


def test_the_first_id_creates_this_installations_word_list(tmp_path):
    path = tmp_path / "client-words.key"
    words = clientwords.installation_words(path)
    assert len(words) == clientwords.INSTALLATION_WORDS == 2048
    assert len(set(words)) == len(words) and set(words) <= set(clientwords.WORDS)
    assert path.stat().st_mode & 0o777 == 0o600


def test_the_list_is_kept(tmp_path):
    path = tmp_path / "client-words.key"
    assert clientwords.installation_words(path) == clientwords.installation_words(path)


def test_each_installation_gets_its_own_list(tmp_path):
    assert set(clientwords.installation_words(tmp_path / "a")) != set(
        clientwords.installation_words(tmp_path / "b")
    )


@pytest.mark.parametrize("content", ["", "amber\notter\n", "notaword\n" * 2048])
def test_a_damaged_list_is_replaced(tmp_path, content):
    path = tmp_path / "client-words.key"
    path.write_text(content)
    words = clientwords.installation_words(path)
    assert len(set(words)) == 2048 and set(words) <= set(clientwords.WORDS)


def test_new_sessions_get_word_ids_from_this_installation(app):
    from isdi.config import get_config

    c = app.test_client()
    c.get("/")
    with c.session_transaction() as s:
        cid = s["clientid"]
    installed = clientwords.installation_words(
        get_config().secrets_dir / "client-words.key"
    )
    assert set(cid.split("-")) <= set(installed)
