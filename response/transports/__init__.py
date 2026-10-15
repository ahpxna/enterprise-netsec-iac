"""Concrete, narrowly scoped firewall/endpoint transports for the response adapters.

Each transport implements only the tiny client protocols declared by the
adapters.  None accepts a caller-supplied URL, alias or command; endpoints and
credential files are fixed at construction from reviewed service configuration.
"""
