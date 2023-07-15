##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163307);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-26136");
  script_xref(name:"IAVA", value:"2022-A-0293");

  script_name(english:"Atlassian Confluence < 7.4.17 / 7.5.x < 7.13.7 / 7.14.x < 7.14.3 / 7.15.x < 7.15.2 / 7.16.x < 7.16.4 / 7.17.x < 7.17.4 XSS (CONFSERVER-79476)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence installed on the remote host is prior to < 7.4.17 / 7.5.x < 7.13.7 / 7.14.x < 7.14.3
/ 7.15.x < 7.15.2 / 7.16.x < 7.16.4 / 7.17.x < 7.17.4. It is, therefore, affected by a vulnerability as referenced in
the CONFSERVER-79476 advisory.

  - Multiple Servlet Filter vulnerabilities have been fixed in Confluence Server and Data Center. These
    vulnerabilities also affect other Atlassian products. For more information, refer to [Atlassian's security
    advisory|https://confluence.atlassian.com/security/multiple-products-security-advisory-
    cve-2022-26136-cve-2022-26137-1141493031.html]. h3. Arbitrary Servlet Filter Bypass (CVE-2022-26136) A
    remote, unauthenticated attacker can bypass Servlet Filters used by first and third party apps. The impact
    depends on which filters are used by each app, and how the filters are used. Atlassian has released
    updates that fix the root cause of this vulnerability, but has not exhaustively enumerated all potential
    consequences of this vulnerability. Only the following attacks have been confirmed: {*}Authentication
    bypass{*}. Sending a specially crafted HTTP request can bypass custom Servlet Filters used by third party
    apps to enforce authentication. A remote, unauthenticated attacker can exploit this to bypass
    authentication used by third party apps. Please note Atlassian has confirmed this attack is possible, but
    has not determined a list of all affected apps. {*}Cross-site scripting (XSS){*}. Sending a specially
    crafted HTTP request can bypass the Servlet Filter used to validate legitimate Atlassian Gadgets, which
    can result in XSS. An attacker that can trick a user into requesting a malicious URL can execute arbitrary
    Javascript in the user's browser. h3. Additional Servlet Filter Invocation (CVE-2022-26137) A remote,
    unauthenticated attacker can cause additional Servlet Filters to be invoked when the application processes
    requests or responses. Atlassian has confirmed and fixed the only known security issue associated with
    this vulnerability: {*}Cross-origin resource sharing (CORS) bypass{*}. Sending a specially crafted HTTP
    request can invoke the Servlet Filter used to respond to CORS requests, resulting in a CORS bypass. An
    attacker that can trick a user into requesting a malicious URL can access the vulnerable application with
    the victim's permissions. h3. Affected versions: * Versions < 7.4.17 * All versions 7.5.x through 7.12.x *
    7.13.x < 7.13.7 * 7.14.x < 7.14.3 * 7.15.x < 7.15.2 * 7.16.x < 7.16.4 * 7.17.x < 7.17.4 * 7.18.0 h3. Fixed
    versions: * 7.4.x >= 7.4.17 ([LTS|https://confluence.atlassian.com/enterprise/long-term-support-
    releases-948227420.html]) * 7.13.x >= 7.13.7 ([LTS|https://confluence.atlassian.com/enterprise/long-term-
    support-releases-948227420.html]) * 7.14.x >= 7.14.3 * 7.15.x >= 7.15.2 * 7.16.x >= 7.16.4 * 7.17.x >=
    7.17.4 * Versions >= 7.18.1 h3. References [Multiple Products Security Advisory
    2022-07-20|https://confluence.atlassian.com/security/multiple-products-security-advisory-
    cve-2022-26136-cve-2022-26137-1141493031.html] (atlassian-CONFSERVER-79476)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-79476");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.4.17, 7.13.7, 7.14.3, 7.15.2, 7.16.4, 7.17.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl");
  script_require_keys("installed_sw/confluence");
  script_require_ports("Services/www", 8080, 8090);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'confluence', port:port, webapp:true);

var constraints = [
  { 'fixed_version' : '7.4.17' },
  { 'min_version' : '7.5.0', 'fixed_version' : '7.13.7' },
  { 'min_version' : '7.14.2', 'fixed_version' : '7.14.3' },
  { 'min_version' : '7.15.1', 'fixed_version' : '7.15.2' },
  { 'min_version' : '7.16.3', 'fixed_version' : '7.16.4' },
  { 'min_version' : '7.17.3', 'fixed_version' : '7.17.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
