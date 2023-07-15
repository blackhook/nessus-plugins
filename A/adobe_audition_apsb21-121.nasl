#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156231);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/24");

  script_cve_id("CVE-2021-44697", "CVE-2021-44698", "CVE-2021-44699");
  script_xref(name:"IAVA", value:"2021-A-0587");

  script_name(english:"Adobe Audition < 14.4.3 / 22.x < 22.1.1 Multiple Privilege Escalation Vulnerabilities (APSB21-121)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by multiple privilege escalation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Adobe Audition install on the remote Windows host is prior to
14.4.3 or 22.x prior to 22.1.1. It is, therefore, affected by multiple privilege escalation vulnerabilities due to out 
of bounds reads. An unauthenticated, local attacker could exploit these to escalate their privileges on an affected 
host. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/audition/apsb21-121.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35b21458");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Audition version 14.4.3, 22.1.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:audition");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_audition_installed.nasl");
  script_require_keys("installed_sw/Adobe Audition", "SMB/Registry/Enumerated");

  exit(0);
}
include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Audition', win_local:TRUE);
var constraints = [
  {'fixed_version': '14.4.1', 'fixed_display': '14.4.3'},
  {'min_version': '22.0', 'fixed_version': '22.1', 'fixed_display': '22.1.1'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
