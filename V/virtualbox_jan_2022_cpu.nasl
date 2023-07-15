#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156846);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id("CVE-2022-21295", "CVE-2022-21394");
  script_xref(name:"IAVA", value:"2022-A-0034-S");

  script_name(english:"Oracle VM VirtualBox (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VirtualBox installed on the remote host is prior to 6.1.32. It is, therefore, affected by multiple  
vulnerabilities as referenced in the January 2022 CPU advisory:

  - Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where 
    Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle 
    VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this 
    vulnerability can result in unauthorized read access to a subset of Oracle VM VirtualBox accessible data. 
    (CVE-2022-21295)

  - Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where
    Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle 
    VM VirtualBox, attacks may significantly impact additional products. Successful attacks of this 
    vulnerability can result in unauthorized access to critical data or complete access to all Oracle VM 
    VirtualBox accessible data. (CVE-2022-21394)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html#AppendixOVIR");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_keys("installed_sw/Oracle VM VirtualBox");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle VM VirtualBox', win_local:TRUE);

var constraints = [{ 'fixed_version' : '6.1.32' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
