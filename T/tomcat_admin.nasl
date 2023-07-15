#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10477);
 script_version("1.33");
 script_cvs_date("Date: 2018/08/03 11:35:08");
 script_cve_id("CVE-2000-0672");
 script_bugtraq_id(1548);

 script_name(english:"Apache Tomcat contextAdmin Arbitrary File Access");
 script_summary(english:"Checks for the presence of /admin");

 script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat web server is affected by an arbitrary file
access vulnerability.");
 script_set_attribute(attribute:"description", value:
"The page /admin/contextAdmin/contextAdmin.html can be accessed. An
attacker can exploit this to read arbitrary files.");
 script_set_attribute(attribute:"solution", value:
"Restrict access to /admin or remove this context, and do not run
Tomcat as root." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/22");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2018 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("tomcat_error_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("installed_sw/Apache Tomcat");

 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_install_count(app_name:"Apache Tomcat", exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:"Apache Tomcat", port:port);

url = "/admin/contextAdmin/contextAdmin.html";
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if(res[0] =~ "^HTTP\/[0-9]\.[0-9] 200" && "<title>Admin Context</title>" >< res[2])
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
  exit(0, "The remote Tomcat install does not appear to have '/admin' accessible remotely on port "+port+".");
