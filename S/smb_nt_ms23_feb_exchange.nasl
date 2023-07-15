#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171442);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/20");

  script_cve_id(
    "CVE-2023-21529",
    "CVE-2023-21706",
    "CVE-2023-21707",
    "CVE-2023-21710"
  );
  script_xref(name:"MSFT", value:"MS23-5023038");
  script_xref(name:"MSKB", value:"5023038");
  script_xref(name:"IAVA", value:"2023-A-0092-S");

  script_name(english:"Security Updates for Microsoft Exchange Server (Feb 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities as referenced in the Feb, 2023 security bulletin.

  - Microsoft Exchange Server Remote Code Execution Vulnerability (CVE-2023-21529, CVE-2023-21706,
    CVE-2023-21707, CVE-2023-21710)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5023038");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB5023038");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21707");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::exchange::get_app_info();

var constraints = [
  { 'fixed_version' : '15.0.1497.47', 'product' : '2013', 'cu' : 23, 'unsupported_cu' : 22, 'kb' : '5023038' },
  { 'fixed_version' : '15.1.2507.21', 'product' : '2016', 'cu' : 23, 'unsupported_cu' : 22, 'kb' : '5023038' },
  { 'fixed_version' : '15.2.986.41', 'product' : '2019', 'cu' : 11, 'unsupported_cu' : 10, 'kb' : '5023038' },
  { 'fixed_version' : '15.2.1118.25', 'product' : '2019', 'cu' : 12, 'unsupported_cu' : 10, 'kb' : '5023038' }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info,
  bulletin:'MS23-02',
  constraints:constraints,
  severity:SECURITY_HOLE
);
