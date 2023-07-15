#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169504);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id("CVE-2022-42945");
  script_xref(name:"IAVA", value:"2023-A-0013");

  script_name(english:"Autodesk DWG TrueView 2023 < 2023.1.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has an install of Autodesk DWG TrueView version 2023 prior to 2023.1.1. It is, therefore, affected by
a remote code execution vulnerability due to DLL search order hijacking.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2022-0024");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2023.1.1 (build 24.2.153.0.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42945");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:dwg_trueview");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_dwg_trueview_installed.nbin");
  script_require_keys("installed_sw/Autodesk DWG TrueView");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Autodesk DWG TrueView', win_local:TRUE);

var constraints = [
  {'min_version': '24.2.0', 'fixed_version': '24.2.153', 'fixed_display': '2023.1.1 (build 153)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
