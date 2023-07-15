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
  script_id(158710);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/09");

  script_cve_id("CVE-2022-23282");

  script_name(english:"Microsoft Paint 3D Code Execution (March 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by a code execution vulnerability..");
  script_set_attribute(attribute:"description", value:
"The Windows 'Paint 3D' app installed on the remote host is affected by a code execution vulnerability. An
attacker who successfully exploited the vulnerability could execute arbitrary code. Exploitation of the vulnerability
requires that a program process a specially crafted file.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-23282");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 6.2105.4017.0, or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var apps = ['Microsoft.MSPaint'];

var app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    { 'fixed_version' : '6.2105.4017.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
