#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170788);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/01");

  script_cve_id("CVE-2022-44877");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/02/07");

  script_name(english:"Linanto Control Web Panel (CWP) 7 < 0.9.8.1147 Command Injection (CVE-2022-44877)");

  script_set_attribute(attribute:"synopsis", value:
"The remote system has a web based control panel application installed that is affected by a command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Linanto Control Web Panel (CWP) 7, a web based control panel application, installed on the remote host is
prior to 0.9.8.1147. It is, therefore, affected by a command injection vulnerability in the login parameter of the
login/index.php page.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2023/Jan/1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Linanto Control Web Panel (CWP) 7 version 0.9.8.1147 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44877");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CWP login.php Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos-webpanel:centos_web_panel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:linanto:control_web_panel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lintano_control_web_panel_nix_installed.nbin");
  script_require_keys("installed_sw/Linanto Control Web Panel");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Linanto Control Web Panel');

var constraints = [
  { 'fixed_version' : '0.9.8.1147' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
