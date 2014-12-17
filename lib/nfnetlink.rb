#!/usr/bin/env ruby

=begin

= File
  nfnetlink.rb

= Author
  Guillaume Delugré <guillaume AT security-labs DOT org>

= Info
  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

=end


require 'rubygems'
require 'ffi'
require 'thread'

module Netfilter

    #
    # Module representing a Netfilter Netlink interface.
    #
    class NetlinkError < Exception; end
    module Netlink
        extend FFI::Library

        begin
            ffi_lib 'libnfnetlink'
        rescue LoadError => exc
            STDERR.puts(exc.message)
            STDERR.puts "Please check that libnfnetlink is installed on your system."
            abort
        end

        attach_function 'nlif_index2name', [:pointer, :uint, :buffer_out], :int
        attach_function 'nlif_get_ifflags', [:pointer, :uint, :buffer_out], :int
        attach_function 'nlif_open', [], :pointer
        attach_function 'nlif_close', [:pointer], :void
        attach_function 'nlif_catch', [:pointer], :int
        attach_function 'nlif_query', [:pointer], :int
        attach_function 'nlif_fd', [:pointer], :int

        def self.interfaces
            InterfaceTable.new
        end
    end

    #
    # Class representing the table of interfaces.
    #
    class InterfaceTable
        IFNAMSIZ = 16
        IFFLAGS = {
            (1 << 0) => :UP,
            (1 << 1) => :BROADCAST,
            (1 << 2) => :DEBUG,
            (1 << 3) => :LOOPBACK,
            (1 << 4) => :POINTTOPOINT,
            (1 << 5) => :NOTRAILERS,
            (1 << 6) => :RUNNING,
            (1 << 7) => :NOARP,
            (1 << 8) => :PROMISC,
            (1 << 9) => :ALLMULTI,
            (1 << 10) => :MASTER,
            (1 << 11) => :SLAVE,
            (1 << 12) => :MULTICAST,
            (1 << 13) => :PORTSEL,
            (1 << 14) => :AUTOMEDIA,
            (1 << 15) => :DYNAMIC,
            (1 << 16) => :LOWER_UP,
            (1 << 17) => :DORMANT,
            (1 << 18) => :ECHO,
        }

        def initialize
            @lock = Mutex.new
            @nlif_handle = Netlink.nlif_open
            raise NetlinkError, "nlif_open has failed" if @nlif_handle.null?

            query_table
            ObjectSpace.define_finalizer(self, proc { Netlink.nlif_close(@nlif_handle) })
        end

        #
        # Gets an interface by index.
        # Return value is a Hash with attributes :name and :flags.
        # Returns nil if interface does not exist.
        #
        def [](index)
            @lock.synchronize {
                update_table
                get_iface(index)
            }
        end

        #
        # Enumerator for the list of interfaces.
        #
        def each
            @lock.synchronize {
                update_table
                for index in 1..65535
                    iface = get_iface(index)
                    next if iface.nil?

                    yield(iface)
                end
            }
        end

        private

        #
        # Process netlink events and updates list of interfaces.
        #
        def update_table
            nlif_fd = Netlink.nlif_fd(@nlif_handle)
            raise NetlinkError, "nlif_fd has failed" if nlif_fd < 0

            nlif_io = IO.new(nlif_fd)
            nlif_io.autoclose = false

            rs, _ws, _es = IO.select([nlif_io], [], [], 0)    

            if rs and rs.length > 0 and rs[0] == nlif_io
                if Netlink.nlif_catch(@nlif_handle) < 0
                    raise NetlinkError, "nlif_catch has failed"
                end
            end

            nlif_io.close
        end

        #
        # Gets the internal list of interfaces.
        #
        def query_table 
            if Netlink.nlif_query(@nlif_handle) < 0
                raise NetlinkError, "nlif_query has failed"
            end
        end

        def get_iface(index)
            ifname = FFI::Buffer.new(IFNAMSIZ, 1, true) 
            ret = Netlink.nlif_index2name(@nlif_handle, index, ifname)
            if ret < 0
                if FFI.errno == Errno::ENOENT::Errno
                    nil
                else
                    raise NetlinkError, "nlif_index2name has failed"
                end
            else
                name = ifname.get_string(0)
                return { :name => name, :flags => [] } if index == 0

                ifflags = FFI::Buffer.new(FFI.type_size(FFI::Type::UINT))
                if Netlink.nlif_get_ifflags(@nlif_handle, index, ifflags) < 0
                    raise NetlinkError, "nlif_get_ifflags has failed"
                end

                flags = ifflags.read_bytes(ifflags.total).unpack("I")[0]
                flags_set = IFFLAGS.select { |bit, name| flags & bit != 0 }.values

                { :index => index,
                  :name => name,
                  :flags => flags_set }
            end
        end
    end
end
