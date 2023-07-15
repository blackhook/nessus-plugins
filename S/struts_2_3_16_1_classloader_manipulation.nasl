#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73203);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-0094");
  script_bugtraq_id(65999);
  script_xref(name:"CERT", value:"719225");

  script_name(english:"Apache Struts 2 'class' Parameter ClassLoader Manipulation");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java framework that is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web application appears to use Struts 2, a web framework that utilizes OGNL (Object-Graph Navigation
Language) as an expression language. The version of Struts 2 in use is affected by a security bypass vulnerability due
to the application allowing manipulation of the ClassLoader via the 'class' parameter, which is directly mapped to the
getClass() method. A remote, unauthenticated attacker can take advantage of this issue to manipulate the ClassLoader
used by the application server, allowing for the bypass of certain security restrictions.

Note that this plugin will only report the first vulnerable instance of a Struts 2 application.

Note also that the application may also be affected by a denial of service vulnerability; however, Nessus has not
tested for this additional issue.");
  # https://cwiki.apache.org/confluence/display/WW/S2-020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2926fce9");
  # https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.3.16.2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e39cc37e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.3.16.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0094");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('http.inc');
include('misc_func.inc');

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
    if (!isnull(match))
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
urls = make_list(urls, '/');

# Struts is slow
timeout = get_read_timeout() * 2;
if(timeout < 10)
  timeout = 10;
http_set_read_timeout(timeout);

urls = list_uniq(urls);

script = SCRIPT_NAME - '.nasl' + '-' + unixtime();

pat = '(Invalid field value for field|No result defined for action)';

foreach url (urls)
{
  res = http_send_recv3(
    method : 'GET',
    port   : port,
    item   : url,
    exit_on_fail : TRUE
  );
  chk1 = egrep(pattern:pat, string:res[2], icase:TRUE);

  vuln_url = url + '?class.classLoader.URLs[0]=' + script;

  res = http_send_recv3(
    method : 'GET',
    port   : port,
    item   : vuln_url,
    fetch404 : TRUE,
    exit_on_fail : TRUE
  );

  pat_match = pregmatch(pattern:pat, string:res[2], icase:TRUE);
  if (
    !isnull(pat_match) &&
    (res[0] =~ "200 OK|404 Not Found") &&
    (!chk1) &&
    (!empty_or_null(pat_match[1]))
  )
  {
    vuln = TRUE;
    output = strstr(res[2], pat_match[1]);
    if (empty_or_null(output)) output = res[2];
    # Stop after first vulnerable Struts app is found
    break;
  }
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_WARNING,
  generic    : TRUE,
  request    : make_list(build_url(qs:vuln_url, port:port)),
  output     : chomp(output)
);
