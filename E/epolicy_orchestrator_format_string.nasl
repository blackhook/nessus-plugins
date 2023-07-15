#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# *Untested*. Probably redundant with plugin# 11075.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11409);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-0690");
  script_bugtraq_id(7111);
  script_xref(name:"SECUNIA", value:"8311");

  script_name(english:"ePolicy Orchestrator HTTP GET Request Remote Format String");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a format string attack.");
  script_set_attribute(attribute:"description", value:
"If the remote web server is ePolicy Orchestrator, an attacker may use
this flaw to execute code with the SYSTEM privileges on this host.");
  # http://web.archive.org/web/20030402001704/http://www.atstake.com/research/advisories/2003/a031703-1.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cc673e1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "httpver.nasl", "http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


function check(port)
{
 local_var	r, res, report;
 if (safe_checks())
 {
   	# To be confirmed...
   	r = http_send_recv3(method: "GET", item:"/SERVER.INI", port:port);
	if (isnull(r)) return 0;
	res = strcat(r[1], '\r\n', r[2]);
	if(("DataSource" >< res && "AgentHttpPort" >< res && "MaxHttpConnection" >< res) ||
	  ("Server: Spipe/1.0" >< res && "MIME-version: 1.0" >< res))
	{
	 report = "
Nessus only detected this vulnerability by looking at the
banner of the web server.
";
	  security_hole(port:port, extra:report);
	}
	return(0);
 }
 if(http_is_dead(port: port)) { return(0); }

 r = http_send_recv3(method: "GET", item: strcat("/", crap(data:"%n%s", length: 64)), port:port);
 if (http_is_dead(port: port, retry: 3))
 {
   report = string("\nNessus detected this vulnerability by crashing the web server.\n");
   security_hole(port:port, extra:report);
 }
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8081);
foreach port (ports)
{
 check(port:port);
}
