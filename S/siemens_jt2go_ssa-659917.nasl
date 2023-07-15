#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174522);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-1709");
  script_xref(name:"IAVA", value:"2023-A-0202-S");

  script_name(english:"Siemens JT2Go < 14.2.0.2 Code Execution (SSA-629917)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Siemens JT2Go installed on the remote Windows hosts is prior to 14.2.0.2. It is, therefore, affected by
a code execution vulnerability due to a stack-based buffer overflow in the APDFL.dll library. When a specially-crafted
file is opened by an unsuspecting user, arbitrary code can be executed in the context of the program.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-629917.pdf");
  script_set_attribute(attribute:"solution", value:
"Update JT2Go to version 14.2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1709");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siemens:jt2go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_jt2go_win_installed.nbin");
  script_require_keys("installed_sw/Siemens JT2Go");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Siemens JT2Go', win_local:TRUE);

var constraints = [
  { 'fixed_version': '14.2.0.23026', 'fixed_display':'14.2.0.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
