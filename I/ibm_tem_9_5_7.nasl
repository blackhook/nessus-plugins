#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104357);
  script_version("1.6");
  script_cvs_date("Date: 2019/02/26  4:50:09");

  script_cve_id(
    "CVE-2017-1218",
    "CVE-2017-1220",
    "CVE-2017-1222",
    "CVE-2017-1225",
    "CVE-2017-1226",
    "CVE-2017-1228",
    "CVE-2017-1230",
    "CVE-2017-1232",
    "CVE-2017-1521"
  );
  script_bugtraq_id(99916, 101571);

  script_name(english:"IBM BigFix Platform 9.2.x < 9.2.12 / 9.5.x < 9.5.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of the IBM BigFix Server.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Platform
application running on the remote host is 9.2.x prior to 9.2.12, or
9.5.x prior to 9.5.7. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified cross-site request forgery (XSRF)
    vulnerability allows an attacker to execute malicious
    and unauthorized actions transmitted from a user that
    the website trusts. (CVE-2017-1218)

  - An unspecified flaw allows the disclosure of sensitive
    information to unauthorized users. (CVE-2017-1220)

  - A failure to perform an authentication check for a
    critical resource or functionality allowing anonymous
    users access to protected areas. (CVE-2017-1222)

  - An information disclosure vulnerability exists due to
    sensitive information in URL parameters being stored
    in server logs, referrer headers and browser history.
    (CVE-2017-1225, CVE-2017-1226)

  - An information disclosure vulnerability exists due to
    a failure to properly enable the secure cookie
    attribute. An attacker could exploit this vulnerability
    to obtain sensitive information using man in the middle
    techniques. (CVE-2017-1228)

  - An information disclosure vulnerability exists due to
    the use of insufficiently random numbers in a security
    context that depends on unpredictable numbers. This
    weakness allows attackers to expose sensitive
    information by guessing tokens or identifiers.
    (CVE-2017-1230)

  - An information disclosure vulnerability exists as
    sensitive data is transmitted in cleartext.
    (CVE-2017-1232)

  - A cross-site scripting vulnerability allows an attacker
    to embed arbitrary JavaScript code in WebReports
    leading to credentials disclosure within a trusted
    session. (CVE-2017-1521)

IBM BigFix Platform was formerly known as Tivoli Endpoint Manager,
IBM Endpoint Manager, and IBM BigFix Endpoint Manager.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22009673");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Platform version 9.2.12 / 9.5.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1218");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

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

include("vcf.inc");
include("http.inc");

app = "IBM BigFix Server";
port = get_http_port(default:52311, embedded:FALSE);

kb_version = "www/BigFixHTTPServer/"+port+"/version";
version = get_kb_item_or_exit(kb_version);

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app, port);

app_info = vcf::get_app_info(
  app:app,
  port:port,
  kb_ver:kb_version,
  service:TRUE
);

vcf::check_granularity(app_info:app_info, sig_segments:3);

#  9.2.12 / 9.5.7
constraints = [
  { "min_version" : "9.2", "fixed_version" : "9.2.12" },
  { "min_version" : "9.5", "fixed_version" : "9.5.7" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE, xsrf:TRUE});
