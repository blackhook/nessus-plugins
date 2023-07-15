#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35806);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2009-0781");

  script_name(english:"Tomcat Sample App cal2.jsp 'time' Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in Tomcat's cal2.jsp");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server includes an example JSP application, 'cal2.jsp',
that fails to sanitize user-supplied input before using it to generate
dynamic content. An unauthenticated, remote attacker can exploit this
issue to inject arbitrary HTML or script code into a user's browser to
be executed within the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/501538/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 4.1.40 / 5.5.28 / 6.0.20.
Alternatively, apply the appropriate patch referenced in the vendor
advisory or undeploy the Tomcat examples web application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");

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
    port    : port,
    cgi     : '/cal/cal2.jsp',
    qs      : 'time=8am'+ 
              urlencode(str:" STYLE=xss:e/**/xpression(try{a=firstTime" +
                "}catch(e){firstTime=1;alert('"+SCRIPT_NAME+"')});"),
    ctrl_re : 'METHOD=POST ACTION=cal1.jsp',
    pass_re : 'INPUT NAME="time" TYPE=HIDDEN VALUE=8am' +
              ' STYLE=xss:e/\\*\\*/xpression\\(try\\{a=firstTime' +
              '\\}catch\\(e\\)\\{firstTime=1;alert\\(\'' + 
              SCRIPT_NAME + '\'\\)\\}\\);',
    dirs     : make_list("/examples/jsp", "/jsp-examples")
  )
) exit(0, "The Tomcat install listening on port " + port + " is not affected.");
