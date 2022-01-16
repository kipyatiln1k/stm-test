import pytest
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from subnet import min_subnet


def test_subnet_empty_ip_addresses():
    with pytest.raises(ValueError):
        min_subnet({})


def test_subnet_two_types_in_ip_addresses():
    with pytest.raises(ValueError):
        min_subnet({IPv4Address(4123412), IPv6Address(6325345)})


def test_subnet_not_expected_type_in_ip_addresses():
    with pytest.raises(ValueError):
        min_subnet("123")


@pytest.mark.parametrize("ip_addresses, expected_subnet",
                         [
                             (
                                 {
                                     ip_address('192.168.1.2'),
                                     ip_address('192.168.1.3'),
                                     ip_address('192.168.1.5'),
                                 },
                                 ip_network('192.168.1.0/29')
                             ),
                             (
                                 {
                                     ip_address('192.168.0.3'),
                                     ip_address('192.168.0.5'),
                                     ip_address('192.168.0.7'),
                                 },
                                 ip_network('192.168.0.0/29')
                             ),
                             (
                                 {
                                     ip_address('233.168.16.3'),
                                     ip_address('233.168.20.5'),
                                     ip_address('233.168.18.7'),
                                 },
                                 ip_network('233.168.16.0/21')
                             ),
                             (
                                 {
                                     ip_address('233.168.18.7'),
                                 },
                                 ip_network('233.168.18.7/32')
                             ),
                         ])
def test_subnet_ipv4(ip_addresses, expected_subnet):
    assert min_subnet(ip_addresses) == expected_subnet


@pytest.mark.parametrize("ip_addresses, expected_subnet",
                         [
                             (
                                 {
                                     ip_address('ffe0::1:0:0:0'),
                                     ip_address('ffe0::2:0:0:0'),
                                     ip_address('ffe0::4:0:0:0'),
                                     ip_address('ffe0::8:0:0:0'),
                                     ip_address('ffe0::10:0:0:0'),
                                     ip_address('ffe0::20:0:0:0'),
                                     ip_address('ffe0::40:0:0:0'),
                                     ip_address('ffe0::80:0:0:0'),
                                 },
                                 ip_network('ffe0::/72')
                             ),
                             (
                                 {
                                     ip_address('ffe0::1:0:0:0')
                                 },
                                 ip_network('ffe0::1:0:0:0/128')
                             )
                         ])
def test_subnet_ipv6(ip_addresses, expected_subnet):
    assert min_subnet(ip_addresses) == expected_subnet
