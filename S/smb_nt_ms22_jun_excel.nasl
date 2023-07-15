##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162204);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/16");

  script_cve_id("CVE-2022-30173");
  script_xref(name:"MSKB", value:"5002208");
  script_xref(name:"MSKB", value:"5002220");
  script_xref(name:"MSFT", value:"MS22-5002208");
  script_xref(name:"MSFT", value:"MS22-5002220");
  script_xref(name:"IAVA", value:"2022-A-0238-S");

  script_name(english:"Security Updates for Microsoft Excel Products (June 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing a security update. It is, therefore, affected by the following vulnerability:

- A remote code execution vulnerability. An attacker can
  exploit this to bypass authentication and execute
  unauthorized arbitrary commands. (CVE-2022-30173)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002208");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002220");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002220
  -KB5002208");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS22-06';
var kbs = make_list(
  '5002220',
  '5002208'
);

var constraints = [
  { 'kb':'5002220',  'fixed_version': '15.0.5459.1000', 'sp' : 1},
  { 'kb':'5002208', 'channel':'MSI', 'fixed_version': '16.0.5332.1000', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Excel'
);
