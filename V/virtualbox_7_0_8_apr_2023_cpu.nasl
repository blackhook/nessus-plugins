#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174462);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2022-42916",
    "CVE-2023-21987",
    "CVE-2023-21988",
    "CVE-2023-21989",
    "CVE-2023-21990",
    "CVE-2023-21991",
    "CVE-2023-21999",
    "CVE-2023-22000",
    "CVE-2023-22001",
    "CVE-2023-22002"
  );
  script_xref(name:"IAVA", value:"2023-A-0216");

  script_name(english:"Oracle VM VirtualBox <6.1.44, < 7.0.8 (April 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VirtualBox installed on the remote host is prior to 6.144 or 7.0.8. It is, therefore, affected by 
multiple vulnerabilities as referenced in the April 2023 CPU advisory:

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions 
    that are affected are prior to 6.1.44 and prior to 7.0.8. Easily exploitable vulnerability allows high privileged 
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. 
    While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope 
    change). Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. (CVE-2023-21990)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions 
    that are affected are prior to 6.1.44 and prior to 7.0.8. Difficult to exploit vulnerability allows low privileged 
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. 
    While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope 
    change). Successful attacks of this vulnerability can result in takeover of Oracle VM VirtualBox. (CVE-2023-21987)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core (cURL)). Supported 
    versions that are affected are prior to 6.1.44 and prior to 7.0.8. In curl before 7.86.0, the HSTS check could be 
    bypassed to trick it into staying with HTTP. Using its HSTS support, curl can be instructed to use HTTPS directly 
    (instead of using an insecure cleartext HTTP step) even when HTTP is provided in the URL. This mechanism could be 
    bypassed if the host name in the given URL uses IDN characters that get replaced with ASCII counterparts as part 
    of the IDN conversion, e.g., using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII 
    full stop of U+002E (.).(CVE-2022-42916)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e8adfc4");
  # https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e9f1de9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Apr 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42916");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include('vcf.inc');

var app_info = NULL;

if (get_kb_item('installed_sw/Oracle VM VirtualBox'))
  app_info = vcf::get_app_info(app:'Oracle VM VirtualBox', win_local:TRUE);
else
  app_info = vcf::get_app_info(app:'VirtualBox');

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '6.1.44'},
  { 'min_version' : '7.0', 'fixed_version' : '7.0.8' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);