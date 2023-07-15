#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136473);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-0905");
  script_xref(name:"MSKB", value:"4551258");
  script_xref(name:"MSKB", value:"4551259");
  script_xref(name:"MSKB", value:"4538708");
  script_xref(name:"MSKB", value:"4538884");
  script_xref(name:"MSKB", value:"4538885");
  script_xref(name:"MSFT", value:"MS20-4551258");
  script_xref(name:"MSFT", value:"MS20-4551259");
  script_xref(name:"MSFT", value:"MS20-4538708");
  script_xref(name:"MSFT", value:"MS20-4538884");
  script_xref(name:"MSFT", value:"MS20-4538885");
  script_xref(name:"IAVA", value:"2020-A-0094-S");

  script_name(english:"Security Updates for Microsoft Dynamics NAV (Mar 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics NAV install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics NAV install is missing a security update. It is, therefore, affected by a remote code execution
vulnerability due to an issue with the Role-Tailored Client. An authenticated, remote attacker can exploit this to
execute arbitrary commands or elevate privileges.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://support.microsoft.com/en-us/help/4551258/description-of-the-security-update-for-dynamics-nav-2013-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?224f974c");
  # https://support.microsoft.com/en-us/help/4551259/description-of-the-security-update-for-dynamics-nav-2015-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9100ca24");
  # https://support.microsoft.com/en-us/help/4538708/cumulative-update-53-for-microsoft-dynamics-nav-2016-build-51775
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55c80f0b");
  # https://support.microsoft.com/en-us/help/4538884/cumulative-update-40-for-microsoft-dynamics-nav-2017-build-30192
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6939775");
  # https://support.microsoft.com/en-us/help/4538885/cumulative-update-27-for-microsoft-dynamics-nav-2018-build-41203
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?126ea1f7");
  script_set_attribute(attribute:"solution", value:
"The solution varies for different versions of Microsoft Dynamics NAV :

  - Dynamics NAV 2013 R2: Install the update package from KB4551258
  - Dynamics NAV 2015: Install the update package from KB4551259
  - Dynamics NAV 2016: Install Cumulative Update 53 or later
  - Dynamics NAV 2017: Install Cumulative Update 40 or later
  - Dynamics NAV 2018: Install Cumulative Update 27 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0905");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:dynamics_nav");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_nav_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics NAV Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics NAV Server';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.1.51780.0' },   # 2013 R2
  { 'min_version' : '8.0', 'fixed_version' : '8.0.51774.0' },   # 2015
  { 'min_version' : '9.0', 'fixed_version' : '9.0.51775.0' },   # 2016
  { 'min_version' : '10.0', 'fixed_version' : '10.0.30192.0' }, # 2017
  { 'min_version' : '11.0', 'fixed_version' : '11.0.41203.0' }  # 2018
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
