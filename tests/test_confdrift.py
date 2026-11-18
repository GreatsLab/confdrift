from pathlib import Path

from confdrift.cli import main
from confdrift.risk import assess, compress_vlans, expand_vlans, redact
from confdrift.tree import diff, parse

EX = Path(__file__).parent.parent / "examples"


def changes(a, b):
    return diff(parse(a), parse(b))


def test_reordering_top_level_is_not_a_change():
    a = "interface Gi1\n desc a\ninterface Gi2\n desc b\n"
    b = "interface Gi2\n desc b\ninterface Gi1\n desc a\n"
    assert changes(a, b) == []


def test_noise_ignored():
    a = "! Last configuration change at 1\nCurrent configuration : 100 bytes\nntp clock-period 1\nhostname x\n"
    b = "! Last configuration change at 2\nCurrent configuration : 200 bytes\nntp clock-period 2\nhostname x\n"
    assert changes(a, b) == []


def test_child_add_remove_has_path():
    a = "interface Gi1\n ip access-group X in\n"
    b = "interface Gi1\n"
    (c,) = changes(a, b)
    assert c.op == "remove" and c.path == ("interface Gi1",)


def test_single_value_becomes_modify():
    a = "interface Gi1\n description old\n"
    b = "interface Gi1\n description new\n"
    (c,) = changes(a, b)
    assert c.op == "modify" and c.old == "description old"


def test_secondary_ip_is_not_paired():
    a = "interface Vlan1\n ip address 1.1.1.1 255.255.255.0\n"
    b = "interface Vlan1\n ip address 1.1.1.1 255.255.255.0\n ip address 2.2.2.1 255.255.255.0 secondary\n"
    (c,) = changes(a, b)
    assert c.op == "add"


def test_acl_reorder_detected():
    a = "ip access-list extended A\n deny ip any host 1.1.1.1\n permit ip any any\n"
    b = "ip access-list extended A\n permit ip any any\n deny ip any host 1.1.1.1\n"
    (c,) = changes(a, b)
    assert c.op == "reorder"


def test_acl_with_seq_numbers_not_a_reorder():
    a = "ip access-list extended A\n 10 deny ip any host 1.1.1.1\n 20 permit ip any any\n"
    b = "ip access-list extended A\n 20 permit ip any any\n 10 deny ip any host 1.1.1.1\n"
    assert changes(a, b) == []


def test_vlan_helpers():
    assert expand_vlans("10,20-22,99") == {10, 20, 21, 22, 99}
    assert compress_vlans({1, 2, 3, 7, 9, 10}) == "1-3,7,9-10"


def test_trunk_detail():
    a = "interface Gi1\n switchport trunk allowed vlan 10,20,30-32\n"
    b = "interface Gi1\n switchport trunk allowed vlan 10,31,40\n"
    ((ch, rule, detail),) = assess(changes(a, b))
    assert rule.severity == "high"
    assert detail == "pruned 20,30,32, added 40"


def test_redact():
    assert redact("username bob secret 9 $9$abc") == "username bob secret 9 <redacted>"
    assert "Welcome1" not in redact("enable password Welcome1")


def test_example_exit_code(capsys):
    rc = main([str(EX / "core-sw01.before.cfg"), str(EX / "core-sw01.after.cfg"), "--fail-on", "high"])
    out = capsys.readouterr().out
    assert rc == 3
    assert "pruned 30,99, added 40" in out
    assert "Welcome123" not in out


def test_identical_files(capsys):
    f = str(EX / "core-sw01.before.cfg")
    assert main([f, f, "--fail-on", "any"]) == 0
