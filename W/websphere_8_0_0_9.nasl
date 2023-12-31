#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76995);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id(
    "CVE-2013-6323",
    "CVE-2013-6329",
    "CVE-2013-6438",
    "CVE-2013-6738",
    "CVE-2013-6747",
    "CVE-2014-0050",
    "CVE-2014-0076",
    "CVE-2014-0098",
    "CVE-2014-0453",
    "CVE-2014-0460",
    "CVE-2014-0823",
    "CVE-2014-0857",
    "CVE-2014-0859",
    "CVE-2014-0878",
    "CVE-2014-0891",
    "CVE-2014-0963",
    "CVE-2014-0965",
    "CVE-2014-3022"
  );
  script_bugtraq_id(
    64249,
    65156,
    65400,
    66303,
    66914,
    66916,
    67051,
    67238,
    67327,
    67329,
    67335,
    67579,
    67601,
    67720,
    68210,
    68211
  );

  script_name(english:"IBM WebSphere Application Server 8.0 < Fix Pack 9 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 8.0 prior to Fix Pack 9 is running on
the remote host. It is, therefore, affected by the following
vulnerabilities :

  - A cross-site scripting flaw exists within the
    Administration Console, where user input is improperly
    validated. This could allow a remote attacker, with a
    specially crafted request, to execute arbitrary script
    code within the browser / server trust relationship.
    (CVE-2013-6323, PI04777 and PI04880)

  - A denial of service flaw exists within the Global
    Security Kit when handling SSLv2 resumption during the
    SSL/TLS handshake. This could allow a remote attacker
    to crash the program. (CVE-2013-6329, PI05309)

  - A buffer overflow flaw exists in the HTTP server with
    the mod_dav module when using add-ons. This could allow
    a remote attacker to cause a buffer overflow and a
    denial of service. (CVE-2013-6438, PI09345)

  - A cross-site scripting flaw exists within OAuth where
    user input is not properly validated. This could allow
    a remote attacker, with a specially crafted request, to
    execute arbitrary script code within the browser /
    server trust relationship. (CVE-2013-6738, PI05661)

  - A denial of service flaw exists within the Global
    Security Kit when handling X.509 certificate chain
    during the initiation of a SSL/TLS connection. A remote
    attacker, using a malformed certificate chain, could
    cause the client or server to crash by hanging the
    Global Security Kit. (CVE-2013-6747, PI09443)

  - A denial of service flaw exists within the Apache
    Commons FileUpload when parsing a content-type header
    for a multipart request. A remote attacker, using a
    specially crafted request, could crash the program.
    (CVE-2014-0050, PI12648, PI12926 and PI13162)

  - A flaw exists in the Elliptic Curve Digital Signature
    Algorithm implementation which could allow a malicious
    process to recover ECDSA nonces.
    (CVE-2014-0076, PI19700)

  - A denial of service flaw exists in the 'mod_log_config'
    when logging a cookie with an unassigned value. A remote
    attacker, using a specially crafted request, can cause
    the program to crash. (CVE-2014-0098, PI13028)

  - An information disclosure flaw exists in the
    'sun.security.rsa.RSAPadding' with 'PKCS#1' unpadding.
    This many allow a remote attacker to gain timing
    information intended to be protected by encryption.
    (CVE-2014-0453)

  - A flaw exists with 'com.sun.jndi.dns.DnsClient' related
    to the randomization of query IDs. This could allow a
    remote attacker to conduct spoofing attacks.
    (CVE-2014-0460)

  - A flaw exists in the Full and Liberty profiles. A remote
    attacker, using a specially crafted request, could gain
    access to arbitrary files. (CVE-2014-0823, PI05324)

  - An information disclosure flaw exists within the
    Administrative Console. This could allow a network
    attacker, using a specially crafted request, to gain
    privileged access. (CVE-2014-0857, PI07808)

  - A denial of service flaw exists in a web server plugin
    on servers configured to retry failed POST request. This
    could allow a remote attacker to crash the application.
    (CVE-2014-0859, PI08892)

  - An information disclosure flaw exists within Proxy and
    ODR servers. This could allow a remote attacker, using a
    specially crafted request, to gain access to potentially
    sensitive information. (CVE-2014-0891, PI09786)

  - A denial of service flaw exists within the IBM Security
    Access Manager for Web with the Reverse Proxy component.
    This could allow a remote attacker, using specially
    crafted TLS traffic, to cause the application on the
    system to become unresponsive. (CVE-2014-0963, PI17025)

  - An information disclosure flaw exists when handling SOAP
    responses. This could allow a remote attacker to
    potentially gain access to sensitive information.
    (CVE-2014-0965, PI11434)

  - An information disclosure flaw exists. A remote
    attacker, using a specially crafted URL, could gain
    access to potentially sensitive information.
    (CVE-2014-3022, PI09594)");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21676092");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21659548");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21663941");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21667254");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21667526");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21672843");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21673013");
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack 9 for version 8.0 (8.0.0.9) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0050");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl");
  script_require_keys("www/WebSphere");
  script_require_ports("Services/www", 8880, 8881);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:0);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version !~ "^8\.0([^0-9]|$)") audit(AUDIT_NOT_LISTEN, "IBM WebSphere Application Server 8.0", port);
if (version =~ "^[0-9]+(\.[0-9]+)?$") audit(AUDIT_VER_NOT_GRANULAR, "IBM WebSphere Application Server", port, version);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 9)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.9' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM WebSphere Application Server", port, version);
