#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159706);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-27783", "CVE-2022-27784");
  script_xref(name:"IAVA", value:"2022-A-0149-S");

  script_name(english:"Adobe After Effects < 18.4.6 / 22.0 < 22.3 Buffer Overflow Vulnerabilities (APSB22-19)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 18.4.6, or 22.x prior to 22.3. 
It is, therefore, affected by multiple stack-based buffer overflow vulnerabilities. An unauthenticated, local 
attacker could exploit this to cause the execution of arbitrary code. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://helpx.adobe.com/security/products/after_effects/apsb22-19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ca7a9a6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 18.4.6, 22.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27784");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);
var constraints = [
  {'fixed_version': '18.4.6'},
  {'min_version': '22.0', 'fixed_version': '22.2.2', 'fixed_display': '22.3'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
