#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173793);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2023-22809");

  script_name(english:"QNAP QTS / QuTS hero Vulnerability in sudo (QSA-23-11)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS / QuTS hero installed on the remote host is affected by a vulnerability as referenced in the
QSA-23-11 advisory.

  - In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-
    provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append
    arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected
    versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a
    -- argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.
    (CVE-2023-22809)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/QSA-23-11");
  script_set_attribute(attribute:"solution", value:
"Apply the solution referenced in the QSA-23-11 advisory");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22809");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudoedit Extra Arguments Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin", "qnap_quts_hero_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  { 'max_version' : '5.0.1', 'product' : 'QTS', 'fixed_display' : 'QTS 5.0.1.2346 build 20230322', 'Number' : '2346', 'Build' : '20230322' },
  { 'max_version' : '5.0.1', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h5.0.1.2348 build 20230324', 'Number' : '2348', 'Build' : '20230324' }
];
vcf::qnap::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
