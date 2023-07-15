#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152526);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2021-36946");
  script_xref(name:"MSKB", value:"5005368");
  script_xref(name:"MSKB", value:"5005369");
  script_xref(name:"MSFT", value:"MS21-5005368");
  script_xref(name:"MSFT", value:"MS21-5005369");
  script_xref(name:"IAVA", value:"2021-A-0375-S");

  script_name(english:"Security Updates for Microsoft Dynamics NAV (August 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics NAV install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics NAV install is missing a security update. It is, therefore, affected by a 
Cross-site Scripting Vulnerability.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5005368");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5005369");
  script_set_attribute(attribute:"solution", value:
"The solution varies for different versions of Microsoft Dynamics NAV :

  - Dynamics NAV 2017: Install Cumulative Update 56 or later
  - Dynamics NAV 2018: Install Cumulative Update 43 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:dynamics_nav");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_nav_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics NAV Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics NAV Server';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '10.0', 'fixed_version' : '10.0.30601.0' }, # 2017
  { 'min_version' : '11.0', 'fixed_version' : '11.0.47562.0' }  # 2018
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss':TRUE}
);
