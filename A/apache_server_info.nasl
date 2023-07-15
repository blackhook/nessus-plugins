#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10678);
 script_version ("1.29");
 script_cvs_date("Date: 2018/08/09 17:06:37");


 script_name(english:"Apache mod_info /server-info Information Disclosure");
 script_summary(english:"Checks access to /server-info");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses configuration information.");
 script_set_attribute(attribute:"description", value:
"A remote unauthenticated attacker can obtain an overview of the
remote Apache web server's configuration by requesting the URL
'/server-info'.  This overview includes information such as installed
modules, their configuration, and assorted run-time settings.");
  script_set_attribute(attribute:"solution", value:
"Update Apache's configuration file(s) to either disable mod_status or
restrict access to specific hosts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"see_also",value:"https://www.owasp.org/index.php/SCG_WS_Apache");

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/05/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Apache");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port);

res = http_send_recv3(method:"GET", port:port, item:"/server-info");
if ("200" >< res[0] && "Server Information" >< res[2])
{
  security_report_v4(
    port:port,
    request:make_list(build_url(qs:"/server-info", port:port)),
    file:"server-status",
    output:res[2],
    severity:SECURITY_WARNING);
  exit(0);
}

audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);

