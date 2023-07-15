#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102019);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2016-9840",
    "CVE-2016-9841",
    "CVE-2016-9842",
    "CVE-2016-9843",
    "CVE-2017-1203",
    "CVE-2017-1219"
  );
  script_bugtraq_id(95131, 99871, 99916);

  script_name(english:"IBM BigFix Platform 9.1.x < 9.1.1328.0 / 9.2.x < 9.2.11.19 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of the IBM BigFix Server.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Platform
application running on the remote host is 9.1.x prior to 9.1.1328.0 or
9.2.x prior to 9.2.11.19. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds pointer arithmetic error exists in
    zlib within file inftrees.c. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    document, to cause a denial of service condition.
    (CVE-2016-9840)

  - An out-of-bounds pointer arithmetic error exists in
    zlib within file inffast.c. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    document, to cause a denial of service condition.
    (CVE-2016-9841)

  - A flaw exists in zlib in the z_streamp() function
    within file inflate.c that is related to left shifts of
    negative numbers. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    document, to cause a denial of service condition.
    (CVE-2016-9842)

  - An out-of-bounds pointer flaw exists in the crc32_big()
    function within file crc32.c when handling big-endian
    pointer calculations. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    document, to cause a denial of service condition.
    (CVE-2016-9843)

  - A cross-site scripting (XSS) vulnerability exists in
    the web-based user interface due to improper validation
    of user-supplied input before returning it to users. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2017-1203)

  - An XML external entity (XXE) injection flaw exists when
    parsing XML data due to an incorrectly configured XML
    parser accepting XML external entities from untrusted
    sources. An authenticated, remote attacker can exploit
    this, via specially crafted XML data, to disclose
    sensitive information or cause a denial of service
    condition. (CVE-2017-1219)

IBM BigFix Platform was formerly known as Tivoli Endpoint Manager, IBM
Endpoint Manager, and IBM BigFix Endpoint Manager.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.ibm.com/blogs/psirt/ibm-security-bulletin-the-bigfix-platform-versions-9-1-and-9-2-have-security-vulnerabilities-that-have-been-addressed-via-patch-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?192a2e64");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22006014");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Platform version 9.1.1328.0 / 9.2.11.19 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("www/BigFixHTTPServer");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "IBM BigFix Server";
port = get_http_port(default:52311, embedded:FALSE);

version = get_kb_item_or_exit("www/BigFixHTTPServer/"+port+"/version");

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);

if (version !~ "^(\d+\.){2,}\d+$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = NULL;
min_fix = make_array(
  "9.1", "9.1.1328.0",
  "9.2", "9.2.11.19"
);

foreach minver (keys(min_fix))
{
  if (ver_compare(ver:version, minver:minver, fix:min_fix[minver], strict:FALSE) < 0)
  {
    fix = min_fix[minver];
    break;
  }
}

if (isnull(fix))
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

report = "";

source = get_kb_item("www/BigFixHTTPServer/"+port+"/source");
if (!isnull(source))
  report += '\n  Source            : ' + source;

report +=
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, xss:TRUE);
