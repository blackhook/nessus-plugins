#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25289);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2007-1355");
  script_bugtraq_id(24058);

  script_name(english:"Tomcat Sample App hello.jsp 'test' Parameter XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a JSP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server includes an example JSP application that fails
to sanitize user-supplied input before using it to generate dynamic
content in an error page. An unauthenticated, remote attacker can
exploit this issue to inject arbitrary HTML or script code into a
user's browser to be executed within the security context of the
affected site.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/469067/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Undeploy the Tomcat documentation web application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl", "cross_site_scripting.nasl");
  script_require_keys("installed_sw/Apache Tomcat");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

get_install_count(app_name:"Apache Tomcat", exit_if_zero:TRUE);
port = get_http_port(default:8080);
install = get_single_install(app_name:"Apache Tomcat", port:port);

get_kb_item_or_exit("www/"+port+"/generic_xss");

# Send a request to exploit the flaw.
xss = raw_string("<script>alert(", SCRIPT_NAME, ")</script>");
exploit = string("test=", xss);

url = string("/tomcat-docs/appdev/sample/web/hello.jsp?", exploit);
w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
res = w[2];

if (
  "<title>Sample Application JSP Page</title>" >< res &&
  ">Query String:<" >< res
)
{
  # There's a problem if our exploit appears in the query string; eg,
  #   <tr>
  #     <th align="right">Query String:</th>
  #     <td align="left">nessus=<script>alert(tomcat_sample_hello_xss.nasl)</script></td>
  #   </tr>
  qstr = strstr(res, ">Query String:<");
  qstr = qstr - strstr(qstr, "</tr>");
  qstr = strstr(qstr, "<td");
  qstr = qstr - strstr(qstr, "</td>");
  # nb: qstr includes some extra markup.
  if (string(">", exploit) >< qstr)
  {
   if (report_verbosity > 0)
   {
     report = 
      '\n' + 'Nessus was able to exploit the issue using the following URL :' +
      '\n' +
      '\n  ' + build_url(port:port, qs:url) + '\n';
     security_warning(port:port, extra:report);
   }
   else security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
