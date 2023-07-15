#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100511);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-1999-0853");
  script_bugtraq_id(847);

  script_name(english:"Netscape Enterprise Server Basic Authentication Buffer Overflow RCE (EGGBASKET/XP_NS-HTTPD)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the Netscape Enterprise Server running on the
remote host is either version 3.6 or 3.6 SP1. It is, therefore,
affected by a buffer overflow condition in the HTTP Basic
Authentication module of the server. An unauthenticated, remote
attacker can exploit this to execute arbitrary code with elevated
privileges.

EGGBASKET is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/08 by a group known as the Shadow
Brokers.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/x0rz/EQGRP/blob/master/Linux/etc/opscript.txt#L4291");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netscape:enterprise_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "httpver.nasl", "http_version.nasl");
  script_require_keys("Settings/ParanoidReport", "www/iplanet");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("Server: Netscape-Enterprise" >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "Netscape Enterprise Server");

server = strstr(banner, "Server:");
server = server - strstr(server, '\r\n');

# EQGRP dump claims the following are affected:
# Netscape-Enterprise 3.6:
#       solaris 2.6(sun4m only), sun4u & sun4m solaris 2.7 - 2.9

# Netscape-Enterprise/3.6 SP1:
#       sun4m solaris 2.8, sun4m & sun4u solaris 2.9
if(server =~ "^Server:\s+Netscape\-Enterprise\/3\.6(\sSP1)?$")
{
  report =
  '\n  The server reported the following banner : ' +
  '\n  ' + server +
  '\n';
  security_report_v4(port:port, extra: report, severity:SECURITY_HOLE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Netscape Enterprise Server", port);
