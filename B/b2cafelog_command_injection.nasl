#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: pokleyzz <pokleyzz@scan-associates.net>
# To: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
# Cc: tech@scan-associates.net
# Subject: [VulnWatch] b2 cafelog 0.6.1 remote command execution.

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(11667);
  script_bugtraq_id(7738);
  script_version("1.26");

  script_name(english:"CafeLog B2 Multiple Script Remote File Inclusion");
  script_summary(english:"Checks for the presence of 'gm020b2.php'");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
remote file include vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote web server is running CafeLog, a blogging application
written in PHP. The 'blogger-2-b2.php' and 'gm-2-b2.php' scripts are
affected by a flaw that could allow an attacker to inject code. An
attacker could exploit this to execute arbitrary code on the remote
host subject to the privileges of the affected web server." );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/May/317" );
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:W/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) exit(0);


function check(loc)
{
 local_var r, w;
 w = http_send_recv3(item:string(loc, "/b2-tools/gm-2-b2.php?b2inc=http://example.com"),
 	method:"GET", port:port);			
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:".*http://example.com/b2functions\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}


dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}
