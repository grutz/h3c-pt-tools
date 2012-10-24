local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to enumerate Huawei / HP/H3C Locally Defined Users through SNMP
]]

---
-- @output
-- | snmp-hh3c-logins:
-- |   admin
-- |     admin
-- |   h3c
-- |_    h3capadmin

author = "Kurt Grutzmacher"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"snmp-brute"}

-- Version 0.1
-- Created 10/01/2012 - v0.1 - created via modifying other walk scripts


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

--- Gets a value for the specified oid
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @param oid string containing the object id for which the value should be extracted
-- @return value of relevant type or nil if oid was not found
function get_value_from_table( tbl, oid )
	
	for _, v in ipairs( tbl ) do
		if v.oid == oid then
			return v.value
		end
	end
	
	return nil
end

--- Processes the table and creates the script output
--
-- @param tbl table containing <code>oid</code> and <code>value</code>
-- @return table suitable for <code>stdnse.format_output</code>
function process_answer( tbl )
	
  -- h3c-user MIB OIDs (oldoid)
  local h3cUserName = "1.3.6.1.4.1.2011.10.2.12.1.1.1.1"
	local h3cUserPassword = "1.3.6.1.4.1.2011.10.2.12.1.1.1.2"
	local h3cUserLevel = "1.3.6.1.4.1.2011.10.2.12.1.1.1.4"
	local h3cUserState = "1.3.6.1.4.1.2011.10.2.12.1.1.1.5"

  -- hh3c-user MIB OIDs (newoid)
	local hh3cUserName = "1.3.6.1.4.1.25506.2.12.1.1.1.1"
	local hh3cUserPassword = "1.3.6.1.4.1.25506.2.12.1.1.1.2"
	local hh3cUserlevel = "1.3.6.1.4.1.25506.2.12.1.1.1.4"
	local hh3cUserState = "1.3.6.1.4.1.25506.2.12.1.1.1.5"

	local new_tbl = {}
	
	for _, v in ipairs( tbl ) do
		
		if ( v.oid:match("^" .. h3cUserName) ) then
			local item = {}
			local oldobjid = v.oid:gsub( "^" .. h3cUserName, h3cUserPassword)
			local newobjid = v.oid:gsub( "^" .. hh3cUserName, hh3cUserPassword)
      			local users = get_value_from_table( tbl, oldobjid )

      			if ( users == nil ) or ( #users == 0 ) then
	         		local users = get_value_from_table( tbl, newobjid )
      			end

			item.name = v.value
			table.insert( item, users )
			table.insert( new_tbl, item )
		end
	
	end
	
	return new_tbl
	
end

action = function(host, port)

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)	
	local data, oldsnmpoid = nil, "1.3.6.1.4.1.2011.10.2.12.1.1.1"
	local data, newsnmpoid = nil, "1.3.6.1.4.1.25506.2.12.1.1.1"
  	local users = {}
	local status

	socket:set_timeout(5000)
	try(socket:connect(host, port))
	
	status, users = snmp.snmpWalk( socket, oldsnmpoid )
	socket:close()

	if (not(status)) or ( users == nil ) or ( #users == 0 ) then

		-- no status? try new snmp oid
	  	socket:set_timeout(5000)
	  	try(socket:connect(host, port))
		status, users = snmp.snmpWalk( socket. newsnmpoid )
	  	socket:close()

	  	if (not(status)) or ( users == nil ) or ( #users == 0 ) then
		  	return users
    		end
	end
		
	users = process_answer( users )

	nmap.set_port_state(host, port, "open")

	return stdnse.format_output( true, users )
end
