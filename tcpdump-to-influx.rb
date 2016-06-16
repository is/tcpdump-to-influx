#!/usr/bin/ruby

require 'socket'
require 'eventmachine'
require 'influxdb'

Socket.do_not_reverse_lookup = true

def parseAddress(s)
	s0 = s.split('.')
	return s0[0..3].join('.'), s0[4].to_i
end

class R < EM::Connection
  include EM::Protocols::LineText2
	def initialize()
		@influx = InfluxDB::Client.new 'gw',
			username: 'traffic', password: '123___zxy',
			time_precision: 'u'
		@queue = []
	end

	def record(pi)
		return if pi[:length] == 0
		slocal = pi[:saddr].start_with?('192.168')
		dlocal = pi[:daddr].start_with?('192.168')
		return if slocal == dlocal

		if slocal then
			series = 'fout'
		else
			series = 'fin'
		end

		ev = {
		  series: series,
			values: {
				dport: pi[:dport],
				sport: pi[:sport],
				length: pi[:length],
			},
			tags: {
				proto: pi[:proto],
				saddr: pi[:saddr],
				daddr: pi[:daddr],
			},
			timestamp: (pi[:ts].to_f * 1000000).to_i
		}

		#@influx.write_point(series, ev)
		@queue << ev
		if @queue.length > 100 then
			puts(@queue)
			@influx.write_points(@queue)
			@queue.clear
		end
	end

	def receive_line(line)
	  pi = packet(line)
		if !pi then
		  #puts("I: <#{line}>")
		elsif pi == 'ERROR' then
			puts ("E:<#{line}>") if pi == 'ERROR'
		elsif pi.is_a?(Hash) then
		  if pi[:proto] == 'tcp' or pi[:proto] == 'udp' then
				record(pi)
			else
				puts(pi)
			end
		else
			puts(pi)
		end
	end

	def packet(line)
		return nil if line.include?('IP6')
		return nil if line.include?('ARP')
		return nil if line.include?('ICMP')
		return nil if line.include?('igmp')

		if line.include?(' IP ') then
		  tokens = line.split()

			if tokens[5]  == 'tcp' then
				srcaddr, srcport = parseAddress(tokens[2])
				dstaddr, dstport = parseAddress(tokens[4].chomp(':'))
				length = tokens[6].to_i
				return {
					proto: 'tcp',
					saddr: srcaddr,
					sport: srcport,
					daddr: dstaddr,
					dport: dstport,
					length: length,
					ts: tokens[0],
				}
			elsif tokens[5] == 'UDP,' then
				srcaddr, srcport = parseAddress(tokens[2])
				dstaddr, dstport = parseAddress(tokens[4].chomp(':'))
				length = tokens[7].to_i
				return {
					proto: 'udp',
					saddr: srcaddr,
					sport: srcport,
					daddr: dstaddr,
					dport: dstport,
					length: length,
					ts: tokens[0],
				}
			end

			c = 0
			for i in tokens
				puts("#{c}: #{i}")
				c += 1
			end
			return "----"
		end
		return 'ERROR'
	end

	def unbind
	end
end

EM.run do
	EM.start_server '0.0.0.0', 1212, R
end

# vim: ai ts=2 noexpandtab
