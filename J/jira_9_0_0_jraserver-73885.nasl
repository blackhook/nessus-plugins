##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162398);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/19");

  script_cve_id("CVE-2020-9493");

  script_name(english:"Atlassian Jira 8.13.x < 8.13.21 / 8.20.x < 8.20.9 / 8.22.x < 8.22.3 / 9.0.0 SQLI (JRASERVER-73885)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira installed on the remote host is prior to 8.13.x < 8.13.21 / 8.20.x < 8.20.9 / 8.22.x <
8.22.3 / 9.0.0. It is, therefore, affected by a vulnerability as referenced in the JRASERVER-73885 advisory.

  - The version of {{log4j}} used by Jira has been updated from version *1.2.7-atlassian-3* to
    *1.2.7-atlassian-16* to address the following vulnerabilities:
    [CVE-2021-4104|https://www.cve.org/CVERecord?id=CVE-2021-4104] JMSAppender is vulnerable to a
    deserialization flaw. A local attacker with privileges to update the Jira configuration can exploit this
    to execute arbitrary code. Jira is not configured to use JMSAppender, nor does Atlassian provide any
    documentation on using JMSAppender with Jira. Atlassian has [remediated this vulnerability by preventing
    external JNDI lookups|https://bitbucket.org/atlassian/log4j1/pull-requests/9] in the Atlassian version of
    {{{}log4j{}}}. [CVE-2020-9493|https://www.cve.org/CVERecord?id=CVE-2020-9493] and
    [CVE-2022-23307|https://www.cve.org/CVERecord?id=CVE-2022-23307] Apache Chainsaw is bundled with {{log4j}}
    1.2.x, and is vulnerable to a deserialization flaw. A remote, unauthenticated attacker could exploit this
    to execute arbitrary code. Please note that Chainsaw is a log viewer that is designed to be executed
    manually. It is not required by Jira, nor is it executed by default, nor does Atlassian provide any
    documentation on using Chainsaw with Jira. Atlassian has [remediated this vulnerability by removing
    Chainsaw|https://bitbucket.org/atlassian/log4j1/commits/3a06f7e94efa98331a875532212a3005fd9766d0] from the
    Atlassian version of {{{}log4j{}}}. [CVE-2022-23302|https://www.cve.org/CVERecord?id=CVE-2022-23302]
    JMSSink is vulnerable to a deserialization flaw. A local attacker with privileges to update the Jira
    configuration can exploit this to execute arbitrary code. Jira is not configured to use JMSSink by
    default, nor does Atlassian provide any documentation on using JMSSink with Jira. Atlassian has
    [remediated this vulnerability by removing
    JMSSink|https://bitbucket.org/atlassian/log4j1/commits/48b34334e5278dfd52b361b1ec6943ca4c3b997e] from the
    Atlassian version of {{{}log4j{}}}. [CVE-2022-23305|https://www.cve.org/CVERecord?id=CVE-2022-23305]
    JDBCAppender is vulnerable to a SQL injection flaw when configured to use the message converter
    ({{{}%m{}}}). A remote, unauthenticated attacker can exploit this to execute arbitrary SQL queries. Jira
    is not configured to use JDBCAppender by default, nor does Atlassian provide any documentation on using
    JDBCAppender with Jira. Atlassian has [remediated this vulnerability by removing
    JDBCAppender|https://bitbucket.org/atlassian/log4j1/commits/b933fe460d64ccfc027b4efee74a5ce1875fe3be] from
    the Atlassian version of {{{}log4j{}}}. Affected versions of Jira: * Versions < 8.13.21 * All versions
    8.14.x through 8.19.x * Versions 8.21.x * Versions 8.22.x < 8.22.3 Fixed versions of Jira: * Versions
    8.13.x >= 8.13.21 * Versions 8.20.x >= 8.20.9 * Versions 8.22.x >= 8.22.3 * Versions >= 9.0.0 (atlassian-
    JRASERVER-73885)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-73885");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.13.21, 8.20.9, 8.22.3, 9.0.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9493");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

var constraints = [
  { 'min_version' : '8.13.20', 'fixed_version' : '8.13.21' },
  { 'min_version' : '8.20.8', 'fixed_version' : '8.20.9' },
  { 'min_version' : '8.22.2', 'fixed_version' : '8.22.3', 'fixed_display' : '8.22.3 / 9.0.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'sqli':TRUE}
);
