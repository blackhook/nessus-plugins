##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163306);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-26136", "CVE-2022-26137");
  script_xref(name:"IAVA", value:"2022-A-0293");

  script_name(english:"Atlassian Jira < 8.13.22 / 8.14.x < 8.20.10 XSS (JRASERVER-73897)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira installed on the remote host is prior to < 8.13.22 / 8.14.x < 8.20.10. It is, therefore,
affected by a vulnerability as referenced in the JRASERVER-73897 advisory.

  - Multiple Servlet Filter vulnerabilities have been fixed in Jira Server and Data Center. These
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
    the victim's permissions. h3. Affected versions: * Versions < 8.13.22 * All versions 8.14.x through 8.19.x
    * 8.20.x < 8.20.10 * All versions 8.21.x * 8.22.x < 8.22.4 h3. Fixed versions: * 8.13.x >= 8.13.22
    ([LTS|https://confluence.atlassian.com/enterprise/long-term-support-releases-948227420.html]) * 8.20.x >=
    8.20.10 ([LTS|https://confluence.atlassian.com/enterprise/long-term-support-releases-948227420.html]) *
    8.22.x >= 8.22.4 (!) 8.22.4 contains a [high impact non-security
    bug|http://jira.atlassian.com/browse/JRASERVER-73875]. Atlassian recommends updating to latest version
    (currently 8.22.6). * Versions >= 9.0.0 h3. References [Multiple Products Security Advisory
    2022-07-20|https://confluence.atlassian.com/security/multiple-products-security-advisory-
    cve-2022-26136-cve-2022-26137-1141493031.html] (atlassian-JRASERVER-73897)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-73897");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.13.22, 8.20.10 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26137");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

var constraints = [
  { 'fixed_version' : '8.13.22' },
  { 'min_version' : '8.14.0', 'fixed_version' : '8.20.10' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
