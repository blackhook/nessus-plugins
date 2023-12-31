#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(11909);
  script_version ("1.24");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id("CVE-2003-1138");
  script_bugtraq_id(8898);

  script_name(english:"Apache Double Slash GET Request Forced Directory Listing");
  script_summary(english:"Sends a GET // HTTP/1.0");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
  script_set_attribute(attribute:"description", value:
"It is possible to obtain the listing of the content of the remote web
server root by sending the request 'GET // HTTP/1.0' This
vulnerability usually affects the default Apache configuration which
is shipped with Red Hat Linux, although it might affect other Linux
distributions or other web server. 

An attacker can exploit this flaw to browse the contents of the remote
web server and possibly find hidden links." );
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/342578/30/0/threaded" );
  script_set_attribute(attribute:"solution", value:
"Create an index file for each directory instead of default welcome
pages." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/27");
  script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/28");
 
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2003-2018 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

res = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if ( "Index of /" >< res) exit(0);

r = http_send_recv3(method:"GET", item:"//", port:port, exit_on_fail: 1);
res = r[2];
if ( !isnull(res) && "Index of /" >< res)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Here are the contents of the initial directory :\n",
      "\n",
      res
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}

audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);
