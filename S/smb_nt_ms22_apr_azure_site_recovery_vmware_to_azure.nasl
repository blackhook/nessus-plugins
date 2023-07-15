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
  script_id(164503);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-26896", "CVE-2022-26897", "CVE-2022-26898");
  script_xref(name:"MSKB", value:"5012960");
  script_xref(name:"MSFT", value:"MS22-5012960");
  script_xref(name:"IAVA", value:"2022-A-0277-S");

  script_name(english:"Security Updates for Microsoft Azure Site Recovery (April 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Azure Site Recovery installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Azure Site Recovery installation on the remote host is missing security updates. It is, therefore, affected by multiple
vulnerabilities:

- A remote code execution vulnerability. An attacker can
exploit this to bypass authentication and execute
unauthorized arbitrary commands. (CVE-2022-26898)

- An information disclosure vulnerability. An attacker can
exploit this to disclose potentially sensitive
information. (CVE-2022-26897, CVE-2022-26896)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-us/topic/update-rollup-61-for-azure-site-recovery-kb5012960-a1cc029b-03ad-446f-9365-a00b41025d39
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff1cb873");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released Update rollup 61 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26898");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
  {'min_version': '9.0', 'fixed_version': '9.48.6349.1'}
];

vcf::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_WARNING
);
