#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84215);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

  script_cve_id("CVE-2015-3306");
  script_bugtraq_id(74238);
  script_xref(name:"EDB-ID", value:"36742");
  script_xref(name:"EDB-ID", value:"36803");

  script_name(english:"ProFTPD mod_copy Information Disclosure");
  script_summary(english:"Checks if SITE CPFR command is available without authentication.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a ProFTPD module that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ProFTPD that is affected by an
information disclosure vulnerability in the mod_copy module due to the
SITE CPFR and SITE CPTO commands being available to unauthenticated
clients. An unauthenticated, remote attacker can exploit this flaw to
read and write to arbitrary files on any web accessible path on the
host.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=4169");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ProFTPD 1.3.5a / 1.3.6rc1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3306");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.3.5 Mod_Copy Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FTP");

  script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
  script_require_keys("ftp/proftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("ftp/proftpd");

# Connect to the FTP server
port = get_ftp_port(default: 21, broken:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

ftp_debug(str:"custom banner");
r = ftp_recv_line(socket:soc);
if (isnull(r)) audit(AUDIT_RESP_NOT, port);

c = 'SITE CPFR /etc/passwd \r\n';
send(socket:soc, data:c);
b = recv(socket:soc, length:3);

ftp_close(socket: soc);

if(b == "350")
{
  if (report_verbosity > 0) security_hole(port:port, extra:'\nNessus received a 350 response from sending the following unauthenticated request :\n\nSITE CPFR /etc/passwd\n');
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'ProFTPD', port);
