from logwatch.cluster import cluster
from logwatch.events import Event


def ev(text, source="app"):
    return Event(source, "f", None, text, {})


def test_same_shape_one_cluster():
    cs = cluster([ev("user 12 took 30ms"), ev("user 99 took 7ms")])
    assert len(cs) == 1
    assert cs[0].count == 2
    assert cs[0].template == "user <*> took <*>ms"


def test_ids_uuids_ips_quotes_masked():
    a = ev('req 3f2b8c1d-aaaa-4bbb-8ccc-0123456789ab from 203.0.113.9 said "hello there" hash deadbeefcafe0011')
    b = ev('req 11111111-2222-4333-8444-555555555555 from 198.51.100.200 said "bye" hash 0123456789abcdef')
    cs = cluster([a, b])
    assert len(cs) == 1
    assert cs[0].template == "req <*> from <*> said <*> hash <*>"


def test_different_sources_split():
    cs = cluster([ev("same text", "a"), ev("same text", "b")])
    assert sorted(c.source for c in cs) == ["a", "b"]
    assert cs[0].id != cs[1].id


def test_id_stable():
    one = cluster([ev("user 1 took 2ms")])
    two = cluster([ev("user 7 took 9ms")])
    assert one[0].id == two[0].id
    assert one[0].id.startswith("c") and len(one[0].id) == 9


def test_sorted_by_count_desc():
    cs = cluster([ev("rare thing")] + [ev("common thing")] * 3)
    assert [c.count for c in cs] == [3, 1]


def test_cap_merges_tail():
    events = []
    for i in range(60):
        word = "kind" + "abcdefghij"[i // 10] + "abcdefghij"[i % 10]
        events += [ev(f"{word} happened")] * (2 if i < 50 else 1)
    cs = cluster(events, max_clusters=50)
    assert len(cs) == 51
    assert cs[-1].template == "<other>"
    assert cs[-1].count == 10
    assert sum(c.count for c in cs) == 110


def test_samples_max_two_and_distinct():
    cs = cluster([ev("user 1 took 2ms"), ev("user 1 took 2ms"), ev("user 3 took 4ms"), ev("user 5 took 6ms")])
    assert cs[0].samples == ("user 1 took 2ms", "user 3 took 4ms")


def test_whitespace_collapsed():
    cs = cluster([ev("a   b\t c"), ev("a b c")])
    assert len(cs) == 1


def test_empty():
    assert cluster([]) == []
