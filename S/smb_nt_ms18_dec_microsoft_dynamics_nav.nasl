#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136616);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-8651");
  script_xref(name:"MSKB", value:"4479232");
  script_xref(name:"MSKB", value:"4479233");
  script_xref(name:"MSFT", value:"MS18-4479232");
  script_xref(name:"MSFT", value:"MS18-4479233");
  script_xref(name:"IAVA", value:"2018-A-0398-S");

  script_name(english:"Security Updates for Microsoft Dynamics NAV (Dec 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics NAV install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics NAV install is missing a security update. It is, therefore, affected by a cross-site scripting
(XSS) vulnerability due to improper validation of user-supplied input before returning it to users. An authenticated,
remote attacker can exploit this, by sending a specially crafted web request, to execute arbitrary script code in a
user's browser session.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4479232");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4479233");
  script_set_attribute(attribute:"solution", value:
"The solution varies for different versions of Microsoft Dynamics NAV :

  - Dynamics NAV 2016: Install Cumulative Update 38 or later
  - Dynamics NAV 2017: Install Cumulative Update 25 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

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
  { 'min_version' : '9.0', 'fixed_version' : '9.0.50785.0' },   # 2016
  { 'min_version' : '10.0', 'fixed_version' : '10.0.26396.0' }  # 2017
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
