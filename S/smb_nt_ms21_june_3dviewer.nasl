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
  script_id(150352);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/09");

  script_cve_id("CVE-2021-31942", "CVE-2021-31943", "CVE-2021-31944");

  script_name(english:"Microsoft 3D Viewer Multiple Vulnerabilities (June 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by multiple vulnerabilties.");
  script_set_attribute(attribute:"description", value:
"The Windows '3D Viewer' app installed on the remote host is affected by multiple vulnerabilities. 

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-31942, CVE-2021-31943)
    
  - An information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive 
    information. (CVE-2021-31944)");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31944
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e914ff80");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31943
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5257edc0");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31942
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdd18cf9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 7.2105.4012.0, or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

apps = ['Microsoft.Microsoft3DViewer'];

app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
    { 'fixed_version' : '7.2105.4012.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
