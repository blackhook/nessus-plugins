# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106231);
  script_version("1.4");
  script_cvs_date("Date: 2018/05/16 19:05:09");

  script_name(english:"Apache .htaccess and .htpasswd Disclosure");
  script_summary(english:"Checks if the .ht files can be accessed.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses information via HTTP request.");
  script_set_attribute(attribute:"description", value:
"The Apache server does not properly restrict access to .htaccess
and/or .htpasswd files. A remote unauthenticated attacker can
download these files and potentially uncover important information.");
  script_set_attribute(attribute:"solution", value:
"Change the Apache configuration to block access to these files.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"see_also",value:"https://www.owasp.org/index.php/SCG_WS_Apache");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include("data_protection.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port);

res = http_send_recv3(method:"GET", port:port, item:"/.htaccess");
if ("200" >< res[0] && !empty_or_null(res[2]))
{
  if (empty_or_null(get_kb_item("www/no404/" + port)) && ("</Directory>" >< res[2] || "</IfModule>" >< res[2]))
  {
    res[2] = data_protection::sanitize_user_full_redaction(output:res[2]);
    security_report_v4(
      port:port,
      request:make_list(build_url(qs:"/.htaccess", port:port)),
      file:".htaccess",
      output:res[2],
      severity:SECURITY_WARNING);
    exit(0);
  }
}

res = http_send_recv3(method:"GET", port:port, item:"/.htpasswd");
if ("200" >< res[0] && !empty_or_null(res[2]))
{
  if (empty_or_null(get_kb_item("www/no404/" + port)))
  {
      res[2] = data_protection::sanitize_user_full_redaction(output:res[2]);
      security_report_v4(
        port:port,
        request:make_list(build_url(qs:"/.htpasswd", port:port)),
        file:".htpasswd",
        output:res[2],
        severity:SECURITY_WARNING);
      exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
