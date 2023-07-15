#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169974);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id("CVE-2022-44689");

  script_name(english:"Security Updates for Windows Subsystem for Linux (WSL2) Elevation of Privilege (December 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The wsl2 installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The wsl2 installation on the remote host is missing a
security update. It is, therefore, affected by an elevation of 
privilege vulnerability. An attacker can exploit this to gain 
elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/microsoft/WSL/releases/tag/1.0.3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released wsl2 1.0.3 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44689");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}
include('vcf.inc');
include('vcf_extras.inc');

var apps = ['MicrosoftCorporationII.WindowsSubsystemForLinux'];

var app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '1.0.3.0' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
