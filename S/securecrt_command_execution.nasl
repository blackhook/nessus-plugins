#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15820);
 script_version("1.16");
 script_cve_id("CVE-2004-1541");
 script_bugtraq_id(11731);

 script_name(english: "SecureCRT telnet URI Arbitrary Configuration Folder Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run through the remote service.");

 script_set_attribute(attribute: "description", value:
"The remote host is using a vulnerable version of SecureCRT, a
SSH/Telnet client built for Microsoft Windows operation systems.

It has been reported that SecureCRT does not safely check the protocol
handler. As a result, an attacker may be able to exploit it by setting
up a malicious SMB share." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SecureCRT 4.1.9 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/23");
 script_cvs_date("Date: 2018/08/22 16:49:14");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_summary(english: "Determines the version of SecureCRT");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Windows");
 script_dependencies("securecrt_remote_overflow.nasl");
 script_require_keys("SMB/SecureCRT/Version");
 exit(0);
}


version = get_kb_item("SMB/SecureCRT/Version");
if ( ! version ) exit(0);

if(egrep(pattern:"^4\.(0\..*|1\.[0-8][^0-9].*)", string:version))
  security_hole(get_kb_item("SMB/transport"));
