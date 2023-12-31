#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26070);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2006-7196");
  script_bugtraq_id(25531);

  script_name(english:"Apache Tomcat Sample App cal2.jsp 'time' Parameter XSS (CVE-2006-7196)");
  script_summary(english:"Checks for an XSS flaw in Tomcat's cal2.jsp.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat web server contains a JSP application that is
affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Apache Tomcat web server includes an example JSP
application, 'cal2.jsp', that fails to sanitize user-supplied input
before using it to generate dynamic content. An unauthenticated,
remote attacker can exploit this issue to inject arbitrary HTML or
script code into a user's browser to be executed within the security
context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/478491/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/478609/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tomcat version 4.1.32 / 5.5.16 or later. Alternatively,
undeploy the Tomcat examples web application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/Apache Tomcat");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"Apache Tomcat", exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:"Apache Tomcat", port:port);

if(
  !test_cgi_xss(
    port     : port,
    cgi      : '/cal/cal2.jsp',
    qs       : 'time=8am<script>alert("'+SCRIPT_NAME+'")</script>',
    ctrl_re  : 'METHOD=POST ACTION=cal1.jsp',
    pass_re  : 'INPUT NAME="time" TYPE=HIDDEN VALUE=8am' +
               '<script>alert\\("'+SCRIPT_NAME+'"\\)</script>',
    dirs     : make_list("/examples/jsp", "/jsp-examples")
  )
) exit(0, "The Tomcat install listening on port " + port + " is not affected.");
