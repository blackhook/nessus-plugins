#%NASL_MIN_LEVEL 80900
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
  script_id(168692);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2022-44704");
  script_xref(name:"IAVA", value:"2022-A-0530-S");
  script_xref(name:"IAVA", value:"2022-A-0533-S");

  script_name(english:"Security Updates for Sysinternals Sysmon (December 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Sysinternals Sysmon installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Sysinternals Sysmon installation on the remote host is missing a
security update. It is, therefore, affected by the following
vulnerability:

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2022-44704)");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sysinternals Sysmon version 14.13, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:sysinternals_sysmon");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sysmon_win_installed.nbin");
  script_require_keys("installed_sw/Sysmon");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Sysmon');

var constraints = [
    { 'min_version': '12.0', 'fixed_version' : '14.1.3.0', 'fixed_display': '14.13'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);