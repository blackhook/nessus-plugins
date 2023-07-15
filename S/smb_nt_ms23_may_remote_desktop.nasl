#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(175364);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id("CVE-2023-28290");

  script_name(english:"Microsoft Remote Desktop App Information Disclosure (May 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Remote Desktop Windows Store App installed on the remote host is prior to 10.2.3006.0. It is, therefore,
affected by an information disclosure vulnerability. When an Microsoft Remote Desktop app for Windows client connects
to the server and the user saves the self-signed certificate, the serial number is used to compare the certificate for
future use. An attacker could swap out a forged certificate with the same serial number resulting in a
Man-In-The-Middle (MiTM) attack.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28290");
  # https://learn.microsoft.com/en-us/azure/virtual-desktop/whats-new-client-microsoft-store
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d6d5c58");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 10.2.3006.0 or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28290");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/10");

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

var apps = ['Microsoft.RemoteDesktop'];

var app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    { 'fixed_version' : '10.2.3006.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
