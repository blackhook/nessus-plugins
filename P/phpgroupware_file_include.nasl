#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Date: 22 Jul 2003 15:05:29 -0000
# From: phil dunn <z3hp@yahoo.com>
# To: bugtraq@securityfocus.com
# Subject: sorry, wrong file


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(11799);
  script_version("1.34");

  script_cve_id("CVE-2006-0524", "CVE-2003-1292");
  script_bugtraq_id(8241, 16426);

  script_name(english:"ashNews 0.83 Multiple Vulnerabilities");
  script_summary(english:"Checks for the presence of ashnews.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include php files hosted on a
third-party server using Ashnews.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

In addition, the application reportedly fails to sanitize the 'id'
parameter before using it in dynamically-generated output, subjecting
users to cross-site scripting attacks." );
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/329910");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2006/Jan/958");
  script_set_attribute(attribute:"solution", value:"Remove the software as it is no longer supported." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-1292");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/07/22");
  script_set_attribute(attribute:"vuln_publication_date", value: "2003/07/22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ashwebstudio:ashnews");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
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
if(!can_host_php(port:port))exit(0);


# Loop through CGI directories.
foreach loc (cgi_dirs()) {
  w = http_send_recv3(method: "GET", item:string(loc, "/ashnews.php?pathtoashnews=http://example.com/"), port:port);
  if (isnull(w)) exit(0);
  r = strcat(w[0], w[1], '\r\n', w[2]);

  if(egrep(pattern:".*http://example.com/ashprojects/newsconfig\.php", string:r))
  {
   	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
