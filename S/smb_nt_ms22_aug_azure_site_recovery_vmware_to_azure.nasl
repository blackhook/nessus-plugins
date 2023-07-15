#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(164502);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-35772",
    "CVE-2022-35774",
    "CVE-2022-35775",
    "CVE-2022-35776",
    "CVE-2022-35780",
    "CVE-2022-35781",
    "CVE-2022-35782",
    "CVE-2022-35783",
    "CVE-2022-35784",
    "CVE-2022-35785",
    "CVE-2022-35786",
    "CVE-2022-35787",
    "CVE-2022-35788",
    "CVE-2022-35789",
    "CVE-2022-35790",
    "CVE-2022-35791",
    "CVE-2022-35799",
    "CVE-2022-35800",
    "CVE-2022-35801",
    "CVE-2022-35802",
    "CVE-2022-35807",
    "CVE-2022-35808",
    "CVE-2022-35809",
    "CVE-2022-35810",
    "CVE-2022-35811",
    "CVE-2022-35812",
    "CVE-2022-35813",
    "CVE-2022-35814",
    "CVE-2022-35815",
    "CVE-2022-35816",
    "CVE-2022-35817",
    "CVE-2022-35818",
    "CVE-2022-35819",
    "CVE-2022-35824"
  );
  script_xref(name:"MSKB", value:"5017421");
  script_xref(name:"MSFT", value:"MS22-5017421");
  script_xref(name:"IAVA", value:"2022-A-0318-S");

  script_name(english:"Security Updates for Microsoft Azure Site Recovery (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Azure Site Recovery installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Azure Site Recovery installation on the remote host is missing
security updates. It is, therefore, affected by multiple
vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-35772,
    CVE-2022-35824)

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2022-35774, CVE-2022-35775, CVE-2022-35780,
    CVE-2022-35781, CVE-2022-35782, CVE-2022-35783,
    CVE-2022-35784, CVE-2022-35785, CVE-2022-35786,
    CVE-2022-35787, CVE-2022-35788, CVE-2022-35789,
    CVE-2022-35790, CVE-2022-35791, CVE-2022-35799,
    CVE-2022-35800, CVE-2022-35801, CVE-2022-35802,
    CVE-2022-35807, CVE-2022-35808, CVE-2022-35809,
    CVE-2022-35810, CVE-2022-35811, CVE-2022-35812,
    CVE-2022-35813, CVE-2022-35814, CVE-2022-35815,
    CVE-2022-35816, CVE-2022-35817, CVE-2022-35818,
    CVE-2022-35819)

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2022-35776)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://prod.support.services.microsoft.com/en-us/topic/update-rollup-63-for-azure-site-recovery-992e63af-aa94-4ea6-8d1b-2dd89a9cc70b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce617fc8");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released Update rollup 63 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35802");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_site_recovery_vmware_to_azure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_site_recovery_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Microsoft Azure Site Recovery", "SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_name = "Microsoft Azure Site Recovery";
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  {'min_version': '9.0', 'fixed_version': '9.50.6419.1'}
];

vcf::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_HOLE
);
