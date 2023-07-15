#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159064);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/03");

  script_cve_id("CVE-2021-43890");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/29");

  script_name(english:"Microsoft App Installer Security Updates (December 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The app installer installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The app installer installation on the remote host is missing a
security update. It is, therefore, affected by a session spoofing 
vulnerability. An attacker can exploit this if the user opens a 
specially crafted attachment. This will allow the attacker to perform 
actions with the privileges of the user.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43890");
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/en-us/p/app-installer/9nblggh4nns1");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released an update to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43890");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:app_installer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
 
var apps = ['Microsoft.DesktopAppInstaller'];
 
var app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);
 
vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
    { 'min_version': '1.11.0.0', 'fixed_version' : '1.11.13404.0'},
    { 'min_version': '1.16.0.0', 'fixed_version' : '1.16.13405.0'}
];
 
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);