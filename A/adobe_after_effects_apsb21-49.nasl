#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150503);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id(
    "CVE-2021-28600",
    "CVE-2021-28601",
    "CVE-2021-28602",
    "CVE-2021-28603",
    "CVE-2021-28604",
    "CVE-2021-28605",
    "CVE-2021-28607",
    "CVE-2021-28608",
    "CVE-2021-28609",
    "CVE-2021-28610",
    "CVE-2021-28611",
    "CVE-2021-28612",
    "CVE-2021-28614",
    "CVE-2021-28615",
    "CVE-2021-28616"
  );
  script_xref(name:"IAVA", value:"2021-A-0267-S");

  script_name(english:"Adobe After Effects < 18.2.1 Multiple Vulnerabilities (APSB21-49)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is
prior to 18.2.1. It is, therefore, affected by multiple vulnerabilities,
including the following:

- A vulnerability exists allowing access of memory location after the end of the
  buffer. An attacker can exploit this to execute arbitrary code on an affected
  system. (CVE-2021-28602, CVE-2021-28605, CVE-2021-28607)

- A heap-based buffer overflow vulnerability exists in Adobe After Effects. An
  attacker can exploit this to execute  arbitrary code on an affected system.
  (CVE-2021-28603, CVE-2021-28604, CVE-2021-28608, CVE-2021-28610)

- An Stack-based Buffer Overflow vulnerability exists in Adobe After Effects. An
  attacker can exploit this to execute arbitrary code on an affected system.
  (CVE-2021-28606)

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version   number.");
  # https://helpx.adobe.com/security/products/after_effects/apsb21-49.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40dfcf1a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 18.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '18.2.1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
