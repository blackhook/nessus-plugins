#
# Copyright (C) 2004-2010 KK Liu
#

#
# rev 1.0: MoonLit detection - 07/30/2004
# rev 1.1: Description changes
# rev 1.2: Bug fixed - 10/28/2004 add statement to handle ret << 29 eq 0x80000000 
#

# Changes by Tenable:
# - Revised plugin title, formatting (11/04/10)

include("compat.inc");

if(description)
{
 script_id(15586);
 script_version ("$Revision: 1.12 $");
 script_cvs_date("$Date: 2013/01/30 17:04:32 $");

 script_name(english:"MoonLit Virus Backdoor Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a malicious application installed." );
 script_set_attribute(attribute:"description", value:
"The system is infected by the MoonLit virus, the backdoor port is 
open.

Backdoor.Moonlit is a Trojan horse program that can download and 
execute files, and may act as a proxy server." );
  # http://www.symantec.com/security_response/writeup.jsp?docid=2004-072717-5851-99
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37577ce7" );
 script_set_attribute(attribute:"solution", value:
"Ensure all MS patches are applied as well as the latest AV 
definitions." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/30");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Detect MoonLit virus");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 KK Liu");
 script_family(english:"Backdoors");
 exit(0);
}

#=============================================================================
# NASL supports only 2 data type - string & integer, and not "long int" support
# so we need to work around the "sign" issue
#=============================================================================
function doGetPortFromIP(dst)
{
	local_var ip, MAGIC, retval, ret2;
	
	ip = split(dst, sep: ".", keep: 0);
	retval = int(ip[0])*256*256*256 + int(ip[1])*256*256 + int(ip[2])*256 + int(ip[3])*1;
	#display ('retval = ', retval , '\n');
	MAGIC = 0x6D617468;

	retval = ((retval >>> 5)|(retval << 27));
	
	#display ('or-retval = ', retval , '\n');

	
	#original cod in C: retval += (retval >= (retval + MAGIC)) ? MAGIC + 1 : MAGIC;
	#display ('retval = ', retval , ', MAGIC =', MAGIC,'\n');
	if ((retval < 0) && (retval + MAGIC >= 0)) MAGIC += 1;
	retval += MAGIC;
	
	#display ('retval+MAGIC = ', retval , '\n');
	
	#KK - 2004-10-28
	#check if retval << 29 eq 0x80000000
	ret2 = retval << 30;
	if (ret2 == 0)
	{
		# 0x80000000 mod 0xFAD9 = 0xB87 = 2951
		return((((retval >>> 3)+ 2951) % 0xFAD9) + 1031);	
	}
	else 
	{
		#ret2 = retval << 29;
		#ret1 = retval >>> 3;
		#display ('val1 = ', ret1, ', val2 =', ret2 , '\n');
		#display ('val1|val2 = ', ret1 | ret2, '\n');
			
		#if result after the shift is negative, int(0x80000000) < 0
		#we add back - 0x80000000 div 0xFAD9 = 33441

		#if ((retval >>> 3)|(retval << 29) < 0)
		#display ('-or =' , ((retval >>> 3)|(retval << 29)) - 0xFAD9 * 33441, '\n');
		#else display ('+or =' , ((retval >>> 3)|(retval << 29)), '\n');
		
		if ((retval >>> 3)|(retval << 29) < 0)
			return(((((retval >>> 3)|(retval << 29)) - 0xFAD9 * 41801) % 0xFAD9) + 1031);
		else return((((retval >>> 3)|(retval << 29)) % 0xFAD9) + 1031);
	}
}


hostip = get_host_ip();
dst = string(hostip);
port = doGetPortFromIP(dst:dst);
#display ('port = ', port, '\n');

if ( get_port_state(port) ) 
{
	#req = string("a");
	soc = open_sock_tcp(port);
	if ( soc ) 
	{
		#send(socket:soc, data:req);
		r = recv(socket:soc, length:10);
		if ( r && (strlen(r) == 2) ) security_hole(port); 
	}
 
}

