#!/usr/bin/env ruby

require 'nfnetlink'

Netfilter::Netlink.interfaces.each do |iface|
    puts "[%d] %12s: %s" % [ iface[:index], iface[:name], iface[:flags].join(", ") ]
end
