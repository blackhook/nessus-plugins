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
  script_id(164501);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2022-30181",
    "CVE-2022-33641",
    "CVE-2022-33642",
    "CVE-2022-33643",
    "CVE-2022-33650",
    "CVE-2022-33651",
    "CVE-2022-33652",
    "CVE-2022-33653",
    "CVE-2022-33654",
    "CVE-2022-33655",
    "CVE-2022-33656",
    "CVE-2022-33657",
    "CVE-2022-33658",
    "CVE-2022-33659",
    "CVE-2022-33660",
    "CVE-2022-33661",
    "CVE-2022-33662",
    "CVE-2022-33663",
    "CVE-2022-33664",
    "CVE-2022-33665",
    "CVE-2022-33666",
    "CVE-2022-33667",
    "CVE-2022-33668",
    "CVE-2022-33669",
    "CVE-2022-33671",
    "CVE-2022-33672",
    "CVE-2022-33673",
    "CVE-2022-33674",
    "CVE-2022-33675",
    "CVE-2022-33676",
    "CVE-2022-33677",
    "CVE-2022-33678"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Security Updates for Microsoft Azure Site Recovery (July 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Azure Site Recovery installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Azure Site Recovery installation on the remote host is missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
unauthorized arbitrary commands. (CVE-2022-33678, CVE-2022-33676)

  - An elevation of privilege vulnerability. An attacker can
exploit this to gain elevated privileges. (CVE-2022-30181, CVE-2022-33641,
CVE-2022-33642, CVE-2022-33643, CVE-2022-33650, CVE-2022-33651, CVE-2022-33652,
CVE-2022-33653, CVE-2022-33654, CVE-2022-33655, CVE-2022-33656, CVE-2022-33657,
CVE-2022-33658, CVE-2022-33659, CVE-2022-33660, CVE-2022-33661, CVE-2022-33662,
CVE-2022-33663, CVE-2022-33664, CVE-2022-33665, CVE-2022-33666, CVE-2022-33667,
CVE-2022-33668, CVE-2022-33669, CVE-2022-33671, CVE-2022-33672, CVE-2022-33673,
CVE-2022-33674, CVE-2022-33677, CVE-2022-33675)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-us/topic/update-rollup-62-for-azure-site-recovery-e7aff36f-b6ad-4705-901c-f662c00c402b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?414369e8");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released Update rollup 62 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33678");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-33674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_site_recovery_vmware_to_azure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_site_recovery_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Microsoft Azure Site Recovery", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Currently we don't differentiate between Configuration Server and Process Server
# both of which are installed by the unified installer.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_name = "Microsoft Azure Site Recovery";
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  {'min_version': '9.0', 'fixed_version': '9.49.6395.1'}
];

vcf::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_WARNING
);
