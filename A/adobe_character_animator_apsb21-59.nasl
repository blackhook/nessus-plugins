#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151977);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-36000", "CVE-2021-36001");
  script_xref(name:"IAVA", value:"2021-A-0344-S");

  script_name(english:"Adobe Character Animator < 4.4 Multiple Vulnerabilities (APSB21-59)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Character Animator installed on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Character Animator installed on the remote Windows host is prior to 4.4. It is, therefore, 
affected by multiple vulnerabilities including the following:

  - An arbitrary code execution vulnerability exists in Adobe Character Animator. An unauthenticated, remote attacker
  can exploit this to bypass authentication and execute arbitrary commands. (CVE-2021-36000) 

  - A privilege escalation vulnerability exists in Adobe Character Animator due to an out-of-bounds read. An 
  unauthenticated, local attacker can exploit this to gain privileged access to the system. (CVE-2021-36001)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/character_animator/apsb21-59.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9017251e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Character Animator version 4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:character_animator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_character_animator_win_installed.nbin");
  script_require_keys("installed_sw/Adobe Character Animator", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Character Animator', win_local:TRUE);
var constraints = [{'fixed_version': '4.3', 'fixed_display': '4.4'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
