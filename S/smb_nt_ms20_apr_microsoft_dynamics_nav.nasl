#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136474);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/15");

  script_cve_id("CVE-2020-1018", "CVE-2020-1022");
  script_xref(name:"MSKB", value:"4557699");
  script_xref(name:"MSKB", value:"4557700");
  script_xref(name:"MSKB", value:"4549673");
  script_xref(name:"MSKB", value:"4549674");
  script_xref(name:"MSKB", value:"4549675");
  script_xref(name:"MSFT", value:"MS20-4557699");
  script_xref(name:"MSFT", value:"MS20-4557700");
  script_xref(name:"MSFT", value:"MS20-4549673");
  script_xref(name:"MSFT", value:"MS20-4549674");
  script_xref(name:"MSFT", value:"MS20-4549675");
  script_xref(name:"IAVA", value:"2020-A-0158");

  script_name(english:"Security Updates for Microsoft Dynamics NAV (Apr 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics NAV install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics NAV install is missing a security update. It is, therefore, affected by the following
vulnerabilities :

  - An information disclosure vulnerability exists in Dynamics NAV due to the application not properly hiding
    the value of a masked field when showing the records as a chart page. An unauthenticated, remote attacker
    can exploit this to disclose potentially sensitive information. (CVE-2020-1018)

  - A remote code execution vulnerability exists in Dynamics NAV due to an unspecified reason. An
    authenticated, remote attacker can exploit this by convincing a user to connect to a malicious Dynamics
    Business Central client to execute arbitrary commands. (CVE-2020-1022)

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4557699");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4557700");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4549673");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4549674");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4549675");
  script_set_attribute(attribute:"solution", value:
"The solution varies for different versions of Microsoft Dynamics NAV :

  - Dynamics NAV 2013 R2: Install the update package from KB4557699
  - Dynamics NAV 2015: Install the update package from KB4557700
  - Dynamics NAV 2016: Install Cumulative Update 54 or later
  - Dynamics NAV 2017: Install Cumulative Update 41 or later
  - Dynamics NAV 2018: Install Cumulative Update 28 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1022");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:dynamics_nav");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_nav_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics NAV Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics NAV Server';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.1.51833.0' },   # 2013 R2
  { 'min_version' : '8.0', 'fixed_version' : '8.0.51812.0' },   # 2015
  { 'min_version' : '9.0', 'fixed_version' : '9.0.51811.0' },   # 2016
  { 'min_version' : '10.0', 'fixed_version' : '10.0.30219.0' }, # 2017
  { 'min_version' : '11.0', 'fixed_version' : '11.0.41920.0' }  # 2018
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
