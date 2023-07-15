#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been disabled.
# Disabled on 2007/03/26. Deprecated by rusers_output.nasl.
exit(0);

#
# (C) Tenable Network Security, Inc.
#

# This script is disabled

if(description)
{
 script_id(10228);
 script_version ("1.18");
 script_cve_id("CVE-1999-0626");
 
 script_name(english:"RPC rusersd Service Detection");
 
 desc["english"] = "
The rusersd RPC service is running.  It provides an attacker interesting
information such as how often the system is being used, the names of
the users, and more.
	
It usually not a good idea to leave this service open.

Solution :

Disable this service if it is not required.

Risk factor : 

Low";

 script_description(english:desc["english"]);
 script_summary(english:"Checks the presence of a RPC service");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"RPC"); 
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

