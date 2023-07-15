#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11020);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2001-0319");
  script_bugtraq_id(2350);

  script_name(english:"IBM Net.Commerce orderdspc.d2w order_rn Option SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is prone to SQL injection.");
  script_set_attribute(attribute:"description", value:
"The macro orderdspc.d2w in the remote IBM Net.Commerce 3x
is vulnerable to a SQL injection attack via the 'order_rn'
option.

An attacker may use it to abuse your database in many ways.");
  # https://web.archive.org/web/20010420044017/http://archives.neohapsis.com/archives/bugtraq/2001-02/0072.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bddc034");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Commerce Suite version 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/06/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:net.commerce");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2002-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_keys("www/ibm-http");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

w = http_send_recv3(method:"GET", item:"/cgi-bin/ncommerce3/ExecMacro/orderdspc.d2w/report?order_rn=9';", port:port, exit_on_fail:TRUE);

res = strcat(w[0], w[1], '\r\n', w[2]);

expect1 = "A database error occurred.";
expect2 = "SQL Error Code";
if((expect1 >< res) && (expect2 >< res))
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
