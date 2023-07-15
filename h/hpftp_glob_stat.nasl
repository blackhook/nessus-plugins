#TRUSTED 6d5266df97b705de1c50a1688369822aa90e7254f2bd4b38e7521184216b3ce2b362264b51dfd677dbc0f04ed975068352cce88d6885c56134d819e2fca37649975b33b5541a0af6a78f7ddde2b5221350bb3284d17f7c381358a4ca417a7a4f9e970462a2192047c669713e8f2679457cc295b138d1eb372a5b7dc94c61a0ac74c334a406d2f626f96a3e24fb3a4fc12b2c1e97484407ece92242dd14112bdd94c0634dea5524c6a3e9e5caeaf4b471d0929a2e9228c65ffcf017f9799d6581596968d46f603ea47ab2cf50aadfe11c907ce49739ba7391667f6c2463910e094ce471cb6ae4a25ae5f9c7e9faf38c8a607dfd066910637b50020856e1cfdddd95c87405dcc9a3f3a96e29dc9af478d41ed436f884e776e36e00962693a596130c8cd8d6f258e3e0e52ed0c04dac4a457abe62192273c18b5220fec2a9f8328ab77ecf2251a2a7dab365e2ec62d7dc3885c0e90392c106f6b403667e550195464091806c4d65f99775d401cb31cbddcfca02743d49652849ce1cccd2a18ab43bb0a0831edee32751c797134469e531e5072d5037a9b3513e276ac38663513c5b7e157fe0163730293a427e603bc2155bdac9db479eeec5ef941882a6296d5600b16844367ac84fc72a07f1df851cc43dd60479b87856b4aaa2993d8fae589bdccbc3e95b604d375752edfe0d337d692c82ed61b05a47eae3e6ba21a662341275
###
# (C) Tenable Network Security, Inc.
#

# TODO: have not observed enough HP-UX FTP banners, safecheck
# is inaccurate and even wrong!
#
# TODO: do not check other FTPD 
#
# From COVERT-2001-02:
# "when an FTP daemon receives a request involving a
# file that has a tilde as its first character, it typically runs the
# entire filename string through globbing code in order to resolve the
# specified home directory into a full path.  This has the side effect
# of expanding other metacharacters in the pathname string, which can
# lead to very large input strings being passed into the main command
# processing routines. This can lead to exploitable buffer overflow
# conditions, depending upon how these routines manipulate their input."
#

include("compat.inc");

if (description)
{
 script_id(11372);
 script_version("1.29");
 script_cvs_date("Date: 2018/10/10 14:50:53");

 script_cve_id("CVE-2001-0248");
 script_bugtraq_id(2552);
 script_xref(name:"CERT-CC", value:"CA-2001-07");

 script_name(english:"HP-UX ftpd glob() Expansion STAT Buffer Overflow");
 script_summary(english:"Checks if the remote HPUX ftp can be buffer overflown");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote HPUX 11 FTP server is affected by a buffer overflow
vulnerability.  The overflow occurs when the STAT command is issued with
an argument that expands into an oversized string after being processed
by the 'glob()' function.");
 # https://web.archive.org/web/20040917154450/http://archives.neohapsis.com/archives/tru64/2002-q3/0017.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91e769e0" );
 script_set_attribute(attribute:"solution", value:"Apply the patch from your vendor.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-0248");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/09/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_writeable_directories.nasl");
 script_require_keys("ftp/login", "ftp/writeable_dir");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here :
#
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

# First, we need access
login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

# Then, we need a writeable directory
wri = get_kb_item("ftp/"+port+"/writeable_dir");
if (! wri) wri = get_kb_item_or_exit("ftp/writeable_dir");

# Connect to the FTP server
soc = ftp_open_and_authenticate( user:login, pass:password, port:port );
if ( soc )
	{
		# We are in

		c = 'CWD ' + string(wri) + '\r\n';
		send(socket:soc, data:c);
		b = ftp_recv_line(socket:soc);
		if(!egrep(pattern:"^250.*", string:b)) exit(0);
		mkd = 'MKD ' + crap(505) + '\r\n';	#505+4+2=511
		mkdshort = 'MKD ' + crap(249) + '\r\n';	#249+4+2=255
		stat = 'STAT ~/*\r\n';

		send(socket:soc, data:mkd);
		b = ftp_recv_line(socket:soc);
		if(!egrep(pattern:"^257 .*", string:b)) {
			#If the server refuse to creat a long dir for some 
			#reason, try a short one to see if it will die.
			send(socket:soc, data:mkdshort);
			b = ftp_recv_line(socket:soc);
			if(!egrep(pattern:"^257 .*", string:b)) exit(0);
		}

		#STAT use control channel
		send(socket:soc, data:stat);
		b = ftp_recv_line(socket:soc);
		if(!b){
			security_hole(port);
			exit(0);
		} else {
			ftp_close(socket:soc);
		}

	}
