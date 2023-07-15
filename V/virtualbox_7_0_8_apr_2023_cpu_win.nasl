#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174463);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2023-21998");
  script_xref(name:"IAVA", value:"2023-A-0216");

  script_name(english:"Oracle VM VirtualBox < 6.1.44, < 7.0.8 (April 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of VirtualBox installed on the remote host is prior to 6.1.44 or 7.0.8. It is, therefore, affected by 
an information disclosure as referenced in the April 2023 CPU advisory. 

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions 
    that are affected are Prior to 6.1.44 and Prior to 7.0.8. Easily exploitable vulnerability allows high privileged 
    attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. 
    While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope 
    change). Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to 
    some of Oracle VM VirtualBox accessible data as well as unauthorized read access to a subset of Oracle VM 
    VirtualBox accessible data (CVE-2023-21998)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e8adfc4");
  # https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e9f1de9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Apr 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21998");

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

  script_dependencies("virtualbox_installed.nasl");
  script_require_ports("installed_sw/Oracle VM VirtualBox");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle VM VirtualBox', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '6.1.44'},
  { 'min_version' : '7.0', 'fixed_version' : '7.0.8' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);