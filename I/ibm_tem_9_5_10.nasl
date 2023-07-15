#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119843);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id(
    "CVE-2018-0739",
    "CVE-2018-1474",
    "CVE-2018-1476",
    "CVE-2018-1478",
    "CVE-2018-1480",
    "CVE-2018-1481",
    "CVE-2018-1484",
    "CVE-2018-1485"
  );

  script_name(english:"IBM BigFix Platform 9.2.x < 9.2.15 / 9.5.x < 9.5.10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Platform
application running on the remote host is 9.2.x prior to 9.2.15, or
9.5.x prior to 9.5.10. It is, therefore, affected by multiple
vulnerabilities :

  - IBM BigFix Platform is vulnerable to HTTP response splitting
    attacks, caused by improper validation of user-supplied input. A
    remote attacker could exploit this vulnerability to inject
    arbitrary HTTP headers and cause the server to return a split
    response, once the URL is clicked. This would allow the attacker
    to perform further attacks, such as Web cache poisoning or
    cross-site scripting, and possibly obtain sensitive information.
    (CVE-2018-1474)

  - IBM BigFix Platform does not renew a session variable after a
    successful authentication which could lead to session
    fixation/hijacking vulnerability. This could force a user to
    utilize a cookie that may be known to an attacker.
    (CVE-2018-1485)

  - OpenSSL is vulnerable to a denial of service. By sending
    specially crafted ASN.1 data with a recursive definition, a
    remote attacker could exploit this vulnerability to consume
    excessive stack memory. (CVE-2018-0739)

In addition, IBM BigFix Platform is also affected by several
additional vulnerabilities including multiple information disclosure
vulnerabilities, a clickjacking vulnerability, multiple sensitive
cookie weakened security vulnerabilities, and a session hijacking
vulnerability.

IBM BigFix Platform was formerly known as Tivoli Endpoint Manager,
IBM Endpoint Manager, and IBM BigFix Endpoint Manager.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=ibm10733605");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Platform version 9.2.15 / 9.5.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1481");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-1476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [
  { "min_version" : "9.2", "fixed_version" : "9.2.15" },
  { "min_version" : "9.5", "fixed_version" : "9.5.10" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
