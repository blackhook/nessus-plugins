##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145222);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id(
    "CVE-2021-2073",
    "CVE-2021-2074",
    "CVE-2021-2086",
    "CVE-2021-2111",
    "CVE-2021-2112",
    "CVE-2021-2119",
    "CVE-2021-2120",
    "CVE-2021-2121",
    "CVE-2021-2123",
    "CVE-2021-2124",
    "CVE-2021-2125",
    "CVE-2021-2126",
    "CVE-2021-2127",
    "CVE-2021-2128",
    "CVE-2021-2129",
    "CVE-2021-2130",
    "CVE-2021-2131"
  );
  script_xref(name:"IAVA", value:"2021-A-0034-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle VM VirtualBox (Jan 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The Prior to 6.1.18 versions of VM VirtualBox installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2021 CPU advisory.

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The 
    supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high 
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise 
    Oracle VM VirtualBox. Successful attacks of this vulnerability can result in unauthorized ability to 
    cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. (CVE-2021-2073,
    CVE-2021-2086, CVE-2021-2111, CVE-2021-2112, CVE-2021-2121, CVE-2021-2124, CVE-2021-2127, CVE-2021-2130)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The
    supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products. Successful attacks of this vulnerability can result in takeover of Oracle VM
    VirtualBox. (CVE-2021-2074)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The 
    supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high 
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise 
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact 
    additional products. Successful attacks of this vulnerability can result in unauthorized access to 
    critical data or complete access to all Oracle VM VirtualBox accessible data. (CVE-2021-2119, 
    CVE-2021-2120, CVE-2021-2128)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The 
    supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high 
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise 
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact 
    additional products. Successful attacks of this vulnerability can result in unauthorized read access to a 
    subset of Oracle VM VirtualBox accessible data. (CVE-2021-2123)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The 
    supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high 
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise 
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact 
    additional products. Successful attacks of this vulnerability can result in unauthorized update, insert or 
    delete access to some of Oracle VM VirtualBox accessible data as well as unauthorized read access to a subset 
    of Oracle VM VirtualBox accessible data. (CVE-2021-2125)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The 
    supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high 
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise 
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact 
    additional products. Successful attacks of this vulnerability can result in unauthorized creation, deletion 
    or modification access to critical data or all Oracle VM VirtualBox accessible data. (CVE-2021-2126,
    CVE-2021-2131)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). The 
    supported version that is affected is Prior to 6.1.18. Easily exploitable vulnerability allows high 
    privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise 
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact 
    additional products. Successful attacks of this vulnerability can result in unauthorized creation, deletion 
    or modification access to critical data or all Oracle VM VirtualBox accessible data as well as unauthorized 
    access to critical data or complete access to all Oracle VM VirtualBox accessible data. (CVE-2021-2129)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2074");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include('vcf.inc');

if (get_kb_item('installed_sw/Oracle VM VirtualBox'))
  app_info = vcf::get_app_info(app:'Oracle VM VirtualBox', win_local:TRUE);
else
  app_info = vcf::get_app_info(app:'VirtualBox');

constraints = [
  { 'min_version' : '6.1', 'fixed_version' : '6.1.18' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
