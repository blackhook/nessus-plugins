#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138088);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2020-1425", "CVE-2020-1457");
  script_xref(name:"IAVA", value:"2020-A-0300-S");

  script_name(english:"Microsoft Windows Codecs Library Multiple Vulnerabilities (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows 'HEVC Video Extensions' or 'HEVC from Device Manufacturer' app
installed on the remote host is affected by two code execution vulnerabilities.
An authenticated, local attacker can exploit either of these vulnerabilities to
bypass additional authentication and execute arbitrary commands.");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1425
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d129577");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1457
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e8b957f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 1.0.31822.0, 1.0.31823.0 or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1425");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

# Thanks to MS for two nearly identical package identity names:
#  Microsoft.HEVCVideoExtension  - HEVC Video Extensions from Device Manufacturer
#  Microsoft.HEVCVideoExtensions - HEVC Video Extensions
apps = ['Microsoft.HEVCVideoExtension', 'Microsoft.HEVCVideoExtensions'];

app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
    { 'fixed_version' : '1.0.31822.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
