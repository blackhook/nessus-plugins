#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(174114);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id("CVE-2023-28287", "CVE-2023-28295");
  script_xref(name:"MSKB", value:"5002213");
  script_xref(name:"MSKB", value:"5002221");
  script_xref(name:"MSFT", value:"MS23-5002213");
  script_xref(name:"MSFT", value:"MS23-5002221");
  script_xref(name:"IAVA", value:"2023-A-0193");

  script_name(english:"Security Updates for Microsoft Publisher Products (April 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Publisher Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Publisher Products are missing a security update. It is, therefore, affected by multiple remote code
execution vulnerabilities. An attacker can exploit these to bypass authentication and execute unauthorized arbitrary
commands.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002213");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002221");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002213
  -KB5002221");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28295");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS23-04';
var kbs = make_list(
  '5002213',
  '5002221'
);

var constraints = [
  { 'kb':'5002213',  'fixed_version': '15.0.5545.1000', 'sp' : 1},
  { 'kb':'5002221', 'channel':'MSI', 'fixed_version': '16.0.5391.1000', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Publisher'
);
