#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175425);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id("CVE-2023-2610");
  script_xref(name:"IAVB", value:"2023-B-0033-S");

  script_name(english:"Vim < 9.0.1532 Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"A text editor installed on the remote Windows host is affected a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the version of Vim installed on the remote Windows host is prior to 9.0.1532. It is,
therefore affected by an integer overflow in the regtilde function that can result in a denial of service condition
by exhausting available system memory, or heap-based code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://huntr.dev/bounties/31e67340-935b-4f6c-a923-f7246bc29c7d/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.0.1532 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2610");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.0.1532' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
