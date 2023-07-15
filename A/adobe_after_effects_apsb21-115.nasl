#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156228);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-43027",
    "CVE-2021-43755",
    "CVE-2021-44188",
    "CVE-2021-44189",
    "CVE-2021-44190",
    "CVE-2021-44191",
    "CVE-2021-44192",
    "CVE-2021-44193",
    "CVE-2021-44194",
    "CVE-2021-44195"
  );
  script_xref(name:"IAVA", value:"2021-A-0590");

  script_name(english:"Adobe After Effects < 18.4.3 / 22.0 < 22.1.1 Multiple Vulnerabilities (APSB21-115)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 18.4.3, or 22.x prior to 22.1.1. 
It is, therefore, affected by multiple vulnerabilities, including the following:

  - Multiple arbitrary code execution vulnerabilities exist in Adobe After Effects. An unauthenticated, 
    local attacker can exploit these to bypass authentication and execute arbitrary commands. 
    (CVE-2021-43755, CVE-2021-44188) 

  - Multiple privilege escalation vulnerabilities exist in Adobe After Effects. An unauthenticated, local 
    attacker can exploit this issue to escalate privileges. (CVE-2021-44189, CVE-2021-44190, CVE-2021-44191,
    CVE-2021-44192, CVE-2021-44193, CVE-2021-44194, CVE-2021-44195, CVE-2021-43027)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://helpx.adobe.com/security/products/after_effects/apsb21-115.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09720458");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 18.4.3, 22.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);
var constraints = [{'min_version': '0.0', 'fixed_version': '18.4.3'},
                   {'min_version': '22.0', 'fixed_version': '22.1.1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
