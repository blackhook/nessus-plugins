#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156024);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/14");

  script_cve_id("CVE-2021-31851", "CVE-2021-31852");
  script_xref(name:"IAVA", value:"2021-A-0571");

  script_name(english:"McAfee Policy Auditor Agent < 6.5.2 Multiple Vulnerabilities (SB10372)");

  script_set_attribute(attribute:"synopsis", value:
"A McAfee Policy Auditor agent installed on the remote host is affected by multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Policy Auditor Agent, installed on the remote host is prior to 6.5.2. It is, therefore, affected
by the following vulnerabilities:

  - A Reflected Cross-Site Scripting vulnerability in McAfee Policy Auditor prior to 6.5.2 allows a remote
    unauthenticated attacker to inject arbitrary web script or HTML via the profileNodeID request parameters.
    The malicious script is reflected unmodified into the Policy Auditor web-based interface which could lead
    to the extraction of end user session token or login credentials. These may be used to access additional
    security-critical applications or conduct arbitrary cross-domain requests. (CVE-2021-31851)
  
  - A Reflected Cross-Site Scripting vulnerability in McAfee Policy Auditor prior to 6.5.2 allows a remote
    unauthenticated attacker to inject arbitrary web script or HTML via the UID request parameter. The
    malicious script is reflected unmodified into the Policy Auditor web-based interface which could lead to
    the extract of end user session token or login credentials. These may be used to access additional
    security-critical applications or conduct arbitrary cross-domain requests. (CVE-2021-31852)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10372");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Policy Auditor Agent version 6.5.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31852");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:policy_auditor");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_policy_auditor_agent_win_installed.nbin");
  script_require_keys("installed_sw/McAfee Policy Auditor Agent");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
if (get_kb_item('SMB/Registry/Enumerated'))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'McAfee Policy Auditor Agent', win_local:win_local);

var constraints = [
  { 'fixed_version' : '6.5.2'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
