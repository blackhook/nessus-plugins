#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10966);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0379");
  script_bugtraq_id(4713);

  script_name(english:"University of Washington imap Server (uw-imapd) BODY Request Remote Overflow");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host, through the 
IMAP server.");
  script_set_attribute(attribute:"description", value:
"The remote version of UW-IMAP is vulnerable to a buffer overflow condition 
that could allow an authenticated attacker to execute arbitrary code on the 
remote host with the privileges of the IMAP server.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to imap-2001a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/05/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:university_of_washington:uw-imap:2000.283");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:university_of_washington:uw-imap:2000.284");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:university_of_washington:uw-imap:2000.287");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:university_of_washington:uw-imap:2000.315");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "logins.nasl");
  script_exclude_keys("imap/false_imap");
  script_require_ports("Services/imap", 143);

  exit(0);
}

#

include("imap_func.inc");

port = get_kb_item("Services/imap");
if(!port)port = 143;
if(!get_port_state(port))exit(0);
banner = get_imap_banner(port:port);
if ( ! banner || !ereg(pattern:"OK .* IMAP4rev1 *200[01]\.[0-9][^ ]* at", string:banner))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

r = recv_line(socket:soc, length:4096);

send(socket:soc, data:string("x capability\r\n"));
r = recv_line(socket:soc, length:4096);

# According to the UW guys, if the server replies with IMAP4 and IMAP4REV1
# then it's vulnerable to the overflow.
if("CAPABILITY IMAP4 IMAP4REV1" >< r ) security_warning(port);
