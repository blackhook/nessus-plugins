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
  script_id(174105);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2023-28291", "CVE-2023-28292");

  script_name(english:"Microsoft Windows Raw Image Extensions Library Multiple Vulnerabilities (April 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by multiple code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows 'Raw Image Extensions' app installed on the remote host is affected by multiple code execution
vulnerabilities:

  - A remote code execution vulnerability exists in the Microsoft Windows Codecs Library Raw Image. An
    attacker who successfully exploited the vulnerability could execute arbitrary code. Exploitation of the
    vulnerability requires that a program process a specially crafted file. (CVE-2023-28291, CVE-2023-28292)
    
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28291");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28292");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 2.1.60611.0 2.0.60612.0 or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var apps = ['Microsoft.RawImageExtension'];

var app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    {'min_version':'1.0', 'fixed_version':'2.0.60612.0'},
    {'min_version':'2.1', 'fixed_version':'2.1.60611.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
