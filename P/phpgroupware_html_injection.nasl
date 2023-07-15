#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14292);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-0504");
  script_bugtraq_id(8088);

  script_name(english:"phpGroupWare index.php Addressbook XSS");

  script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to multiple cross-site scripting 
attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host seems to be running PhpGroupWare, a multi-user 
groupware suite written in PHP.

This version is reportedly prone to multiple HTML injection 
vulnerabilities. The issues present themselves due to a lack of 
sufficient input validation performed on form fields used by 
PHPGroupWare modules. 

A malicious attacker may inject arbitrary HTML and script code using 
these form fields that may be incorporated into dynamically-generated 
web content.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpgroupware.org/");
  script_set_attribute(attribute:"solution", value:
"Update to version 0.9.14.005 or newer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpgroupware:phpgroupware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("phpgroupware_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80, embedded:TRUE);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
if ( ereg(pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-3]\.|14\.0*[0-3]([^0-9]|$)))", string:matches[1]))
 			security_warning(port);
