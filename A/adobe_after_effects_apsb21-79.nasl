#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154713);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/17");

  script_cve_id(
    "CVE-2021-40751",
    "CVE-2021-40752",
    "CVE-2021-40753",
    "CVE-2021-40754",
    "CVE-2021-40755",
    "CVE-2021-40756",
    "CVE-2021-40757",
    "CVE-2021-40758",
    "CVE-2021-40759",
    "CVE-2021-40760",
    "CVE-2021-40761"
  );
  script_xref(name:"IAVA", value:"2021-A-0509-S");

  script_name(english:"Adobe After Effects < 18.4.2 Multiple Vulnerabilities (APSB21-79)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 18.4.2. It is, therefore, affected
by multiple vulnerabilities, including the following:

  - Multiple arbitrary code execution vulnerabilities exist in Adobe After Effects. An unauthenticated, 
    local attacker can exploit these to bypass authentication and execute arbitrary commands. 
    (CVE-2021-40751, CVE-2021-40752, CVE-2021-40753, CVE-2021-40754, CVE-2021-40755, CVE-2021-40757, 
    CVE-2021-40758, CVE-2021-40759, CVE-2021-40760) 

  - Multiple denial of service (DoS) vulnerabilities exist in Adobe After Effects. An unauthenticated, local 
    attacker can exploit this issue to cause the application to stop responding. (CVE-2021-40756, 
    CVE-2021-40761)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://helpx.adobe.com/security/products/after_effects/apsb21-79.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?358a9e9f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 18.4.2, 22.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

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
var constraints = [{'fixed_version': '18.4.2', 'fixed_display': '18.4.2 / 22.0'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
