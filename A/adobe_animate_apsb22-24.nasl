##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162319);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-30664");
  script_xref(name:"IAVA", value:"2022-A-0236-S");

  script_name(english:"Adobe Animate < 21.0.6 / 22.x < 22.0.6 Code Execution (APSB22-24)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Animate installed on remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Animate installed on the remote host is affected by an arbitrary code execution vulnerability due
to an out-of-bounds write. An unauthenticated, local attacker can exploit this to execute code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/animate/apsb22-24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Animate version 21.0.11, 22.0.6, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:animate");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_animate_installed.nbin", "macosx_adobe_animate_installed.nbin");
  script_require_keys("installed_sw/Adobe Animate");

  exit(0);
}

include('vcf.inc');

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Adobe Animate', win_local:win_local);

var constraints = [
  { 'fixed_version' : '21.0.11', 'fixed_display': '21.0.11 / 22.0.6' },
  { 'min_version' : '22.0', 'fixed_version' : '22.0.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
