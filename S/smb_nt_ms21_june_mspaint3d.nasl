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
  script_id(150373);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2021-31945", "CVE-2021-31946", "CVE-2021-31983");

  script_name(english:"Microsoft Paint 3D Multiple Vulnerabilities (June 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows 'Paint 3D' app installed on the remote host is affected by multiple remote code execution vulnerabilities. 
An attacker can exploit these to bypass authentication and execute unauthorized arbitrary commands.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31945
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?941966fe");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31946
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a40919a7");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31983
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99b641c8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 6.2105.4017.0, or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31946");

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

apps = ['Microsoft.MSPaint'];

app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
    { 'fixed_version' : '6.2105.4017.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
