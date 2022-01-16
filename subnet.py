import sys
from typing import Union, Iterable
from ipaddress import (
    IPv4Address, IPv4Network,
    IPv6Address, IPv6Network,
    ip_network
)


def min_subnet(
    ip_addresses: Union[Iterable[IPv4Address], Iterable[IPv6Address]]
) -> Union[IPv4Network, IPv6Network]:
    """Take a set of IP objects and return 
    the minimum subnet object for this set of addresses.

    Args:
        ip_addresses: An Iterable with IPv4Address or IPv6Address.
        All address objects must have the same type.

    Raises:
        ValueError: if ip_addresses is empty or contains more than one ip type. 

    Returns:
        An IPv4Network or IPv6Network object.
    """

    # if ip_addresses is empty, raise the ValueError
    if not ip_addresses:
        raise ValueError("There is no IP addresses in the ip_addresses.")

    # if more than one type of ip in ip addresses, 
    # raise the ValueError
    ip_types = {type(ip) for ip in ip_addresses}
    if len(ip_types) > 1:
        raise ValueError("There are addresses with \
                         different types in the ip_addresses.")
    
    # get the ip type 
    example_ip = list(ip_addresses)[0]
    ip_class = type(example_ip)
    
    # if ip_addresses contains not expected type
    # raise the ValueError
    if ip_class not in (IPv4Address, IPv6Address):
        raise ValueError("There is not ip object in the ip_addresses")
    
    # get the max len of the subnet prefix
    max_prefixlen = example_ip.max_prefixlen

    # get uniqe ips from ip_addresses
    ip_set = set(ip_addresses)

    # if in ip_set only 1 ip
    # return network with this ip address and max prefixlen
    if len(ip_set) == 1:
        return ip_network(f'{example_ip}/{max_prefixlen}')

    # get the binary conjunction of all ips
    conjunction_ip_int = 2 ** max_prefixlen - 1
    for ip in ip_set:
        conjunction_ip_int &= int(ip)

    # get the list with numbers
    # where same bits with conjunction_ip_int is 0
    # and different is 1
    ip_in_subnet_set = [int(ip) ^ conjunction_ip_int
                        for ip in ip_set]

    # get the prefixlen
    host_bits_len = len(bin(int(max(ip_in_subnet_set)))) - 2
    prefixlen = max_prefixlen - host_bits_len

    # get the subnet_ip
    mask_int = 2 ** max_prefixlen - 2 ** (max_prefixlen - prefixlen)
    subnet_ip = ip_class(conjunction_ip_int & mask_int)

    return ip_network(f'{subnet_ip}/{prefixlen}')


def main(args):
    # get the filename
    try:
        filename = args[1]
    except IndexError:
        filename = input("Enter the filename: ")

    # read addresses strings from the file
    with open(filename) as f:
        addres_lst = [line.strip() for line in f.readlines()]

    # get the ip type 
    try:
        _type = args[2]
    except IndexError:
        _type = input("Enter the ip address type: ")

    # get the class of entered type 
    if _type == 'ipv4':
        ip_class = IPv4Address
    elif _type == 'ipv6':
        ip_class = IPv6Address
    else:
        raise Exception(f'{_type} is incorrect ip type')

    # parse the ip addresses
    ip_set = set([ip_class(ip) for ip in addres_lst])

    # get the min subnet
    subnet = min_subnet(ip_set)

    # print the min subnet
    print(f'Result net: {subnet}')


if __name__ == '__main__':
    main(sys.argv)
