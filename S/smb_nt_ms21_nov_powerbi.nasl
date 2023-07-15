#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155143);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-41372");
  script_xref(name:"MSKB", value:"5007903");
  script_xref(name:"MSFT", value:"MS21-5007903");

  script_name(english:"Security Update for Microsoft Power BI Report Server (November 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF) vulnerability exists when Power BI Report Server
Template file (pbix) containing HTML files is uploaded to the server and HTML files are accessed directly by the victim.

Combining these 2 vulnerabilities together, an attacker is able to upload malicious Power BI templates files to the server
using the victim's session and run scripts in the security context of the user and perform privilege escalation in case
the victim has admin privileges when the victim access one of the HTML files present in the malicious Power BI template
uploaded.

The security update addresses the vulnerability by helping to ensure that Power BI Report Server properly sanitize file
uploads.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-us/topic/escalation-of-privilege-possible-in-power-bi-report-server-september-2021-november-9-2021-kb5007903-f0fdda32-18c9-4167-8bfe-58fcc62aebe5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ec061fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade Power BI Report Server to version 15.0.1107.165 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:power_bi_report_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_power_bi_rs_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Power BI Report Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Microsoft Power BI Report Server', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

var constraints = [
  { 'min_version': '0' ,'fixed_version' : '1.12.7977.29537' }
];

vcf::check_version_and_report(app_info:app_info,
                              constraints:constraints,
                              severity:SECURITY_WARNING,
                              flags:{xss:TRUE, xsrf:TRUE});
