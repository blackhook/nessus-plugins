#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168748);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2022-3159", "CVE-2022-3160", "CVE-2022-3161");
  script_xref(name:"IAVA", value:"2022-A-0522-S");

  script_name(english:"Siemens JT2Go < 14.1.0.5 Multiple Vulnerabilities (SSA-360681)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Siemens JT2Go installed on the remote Windows hosts is prior to 14.1.0.5. It is, therefore, affected by
multiple vulnerabilities in the APDFL library that could be triggered when the application reads malicious PDF files.
If a user is tricked to open a malicious PDF file this could lead the application to crash or potentially lead to
arbitrary code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-360681.pdf");
  script_set_attribute(attribute:"solution", value:
"Update JT2Go to version 14.1.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3161");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siemens:jt2go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_jt2go_win_installed.nbin");
  script_require_keys("installed_sw/Siemens JT2Go");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Siemens JT2Go', win_local:TRUE);

var constraints = [
  # There isn't a publically available 14.1.0.5 to get a version number from so this
  # is one build number higher than the one for 14.1.0.4
  { 'fixed_version': '14.1.0.22222', 'fixed_display':'14.1.0.5' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
