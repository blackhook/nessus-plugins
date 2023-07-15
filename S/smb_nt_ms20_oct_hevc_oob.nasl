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
  script_id(142595);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/13");

  script_cve_id("CVE-2020-17022");
  script_xref(name:"IAVA", value:"2020-A-0457-S");

  script_name(english:"Microsoft Windows Codecs Library RCE (October 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows 'HEVC Video Extensions' or 'HEVC from Device Manufacturer' app
installed on the remote host is affected by a remote code execution
vulnerability :

  - A remote code execution vulnerability exists in the way that Microsoft
  Windows Codecs Library handles objects in memory. An attacker who
  successfully exploited the vulnerability could execute arbitrary code.
  Exploitation of the vulnerability requires that a program process a specially
  crafted image file. (CVE-2020-17022)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-17022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7b35e41");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version  1.0.32762.0, 1.0.32763.0, or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17022");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

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
    { 'fixed_version' : '1.0.32762.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
