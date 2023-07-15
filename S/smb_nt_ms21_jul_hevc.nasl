#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151589);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/12");

  script_cve_id(
    "CVE-2021-31947",
    "CVE-2021-33775",
    "CVE-2021-33776",
    "CVE-2021-33777",
    "CVE-2021-33778"
  );
  script_xref(name:"IAVA", value:"2021-A-0318-S");

  script_name(english:"Microsoft Windows HEVC Codecs Library Multiple Vulnerabilities (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows 'HEVC Video Extensions' or 'HEVC from Device Manufacturer' app
installed on the remote host is affected by multiple remote code execution
vulnerabilities. Remote code execution vulnerabilities exists in the Microsoft 
Windows Codecs Library HEVC Extension. An attacker who successfully exploited 
the vulnerabilities could execute arbitrary code. Exploitation of the 
vulnerabilities requires that a program process a specially crafted file.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-31947
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4078abde");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-33775
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?800157d3");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-33776
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdb9707d");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-33777
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?073f382b");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-33778
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?794ab155");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 1.0.41483.0, 1.0.41531.0, or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31947");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
var apps = ['Microsoft.HEVCVideoExtension', 'Microsoft.HEVCVideoExtensions'];

var app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    { 'fixed_version' : '1.0.41483.0', 'fixed_display' : '1.0.41483.0 / 1.0.41531.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
