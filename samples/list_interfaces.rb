#!/usr/bin/env ruby

require 'nfnetlink'

Netfilter::Netlink.interfaces.each do |iface|
    puts "%12s: %s" % [ iface[:name], iface[:flags].join(", ") ]
end
