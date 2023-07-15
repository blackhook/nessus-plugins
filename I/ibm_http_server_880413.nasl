#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144774);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-0211", "CVE-2019-0220");
  script_bugtraq_id(107666, 107670);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"IBM HTTP Server 7.0.0.0 <= 7.0.0.45 / 8.0.0.0 <= 8.0.0.15 / 8.5.0.0 < 8.5.5.16 / 9.0.0.0 < 9.0.5.0 Multiple Vulnerabilities (880413)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM HTTP Server running on the remote host is affected by multiple vulnerabilities related to Apache
HTTP Server, as follows:

  - A vulnerability was found in Apache HTTP Server 2.4.0 to 2.4.38. When the path component of a request URL
    contains multiple consecutive slashes ('/'), directives such as LocationMatch and RewriteRule must account
    for duplicates in regular expressions while other aspects of the servers processing will implicitly
    collapse them. (CVE-2019-0220)

  - In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38, with MPM event, worker or prefork, code executing in
    less-privileged child processes or threads (including scripts executed by an in-process scripting
    interpreter) could execute arbitrary code with the privileges of the parent process (usually root) by
    manipulating the scoreboard. Non-Unix systems are not affected. (CVE-2019-0211)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/880413");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server version 8.5.5.16, 9.0.5.0, or later. Alternatively, upgrade to the minimal fix pack levels
 required by the interim fix and then apply Interim Fix PH09869.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0211");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_http_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM HTTP Server (IHS)");

  exit(0);
}


include('vcf.inc');

app = 'IBM HTTP Server (IHS)';
fix = 'Interim Fix PH09869';

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

if ('PH09869' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
 { 'min_version' : '7.0.0.0', 'max_version' : '7.0.0.45', 'fixed_display' : fix },
 { 'min_version' : '8.0.0.0', 'max_version' : '8.0.0.15', 'fixed_display' : fix },
 { 'min_version' : '8.5.0.0', 'max_version' : '8.5.5.15', 'fixed_display' : '8.5.5.16 or ' + fix },
 { 'min_version' : '9.0.0.0', 'max_version' : '9.0.0.11', 'fixed_display' : '9.0.5.0 or ' + fix }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
