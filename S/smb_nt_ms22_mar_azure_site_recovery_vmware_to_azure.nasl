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
  script_id(164504);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-24467",
    "CVE-2022-24468",
    "CVE-2022-24469",
    "CVE-2022-24470",
    "CVE-2022-24471",
    "CVE-2022-24506",
    "CVE-2022-24515",
    "CVE-2022-24517",
    "CVE-2022-24518",
    "CVE-2022-24519",
    "CVE-2022-24520"
  );
  script_xref(name:"MSKB", value:"5011122");
  script_xref(name:"MSFT", value:"MS22-5011122");
  script_xref(name:"IAVA", value:"2022-A-0116-S");

  script_name(english:"Security Updates for Microsoft Azure Site Recovery (March 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Azure Site Recovery installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Azure Site Recovery installation on the remote host is missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-24467,
    CVE-2022-24468, CVE-2022-24470, CVE-2022-24471,
    CVE-2022-24517, CVE-2022-24520)

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2022-24469, CVE-2022-24506, CVE-2022-24515,
    CVE-2022-24518, CVE-2022-24519)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-us/topic/update-rollup-60-for-azure-site-recovery-kb5011122-883a93a7-57df-4b26-a1c4-847efb34a9e8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f25c270");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released Update rollup 60 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24469");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
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

# MS download for 9.47.6219.1 were taken down with note:
# Links for downloading Configuration Server OVF and Unified Setup for the version 9.47.6219.1 have been taken down due to issues with data corruption.
var constraints = [
  {'min_version': '9.0', 'fixed_version': '9.47.6219.1', 'fixed_display': '9.48.6349.1'}
];

vcf::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_HOLE
);
