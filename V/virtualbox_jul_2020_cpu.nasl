#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138527);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-14628",
    "CVE-2020-14629",
    "CVE-2020-14646",
    "CVE-2020-14647",
    "CVE-2020-14648",
    "CVE-2020-14649",
    "CVE-2020-14650",
    "CVE-2020-14673",
    "CVE-2020-14674",
    "CVE-2020-14675",
    "CVE-2020-14676",
    "CVE-2020-14677",
    "CVE-2020-14694",
    "CVE-2020-14695",
    "CVE-2020-14698",
    "CVE-2020-14699",
    "CVE-2020-14700",
    "CVE-2020-14703",
    "CVE-2020-14704",
    "CVE-2020-14707",
    "CVE-2020-14711",
    "CVE-2020-14712",
    "CVE-2020-14713",
    "CVE-2020-14714",
    "CVE-2020-14715"
  );
  script_xref(name:"IAVA", value:"2020-A-0323-S");

  script_name(english:"Oracle VM VirtualBox (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The Prior to 5.2.44, prior to 6.0.24, and prior to 6.1.12 versions of VM VirtualBox installed on the remote host are
affected by multiple vulnerabilities as referenced in the July 2020 CPU advisory.

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported 
    versions that are affected are Prior to 5.2.44, prior to 6.0.24 and prior to 6.1.12. Easily exploitable 
    vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox 
    executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks 
    may significantly impact additional products. Successful attacks of this vulnerability can result in 
    takeover of Oracle VM VirtualBox. Note: The CVE-2020-14628 is applicable to Windows VM only. 
    (CVE-2020-14628, CVE-2020-14629, CVE-2020-14703, CVE-2020-14704, CVE-2020-14711, CVE-2020-14714, 
    CVE-2020-14715)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported 
    versions that are affected are Prior to 5.2.44, prior to 6.0.24 and prior to 6.1.12. Difficult to exploit 
    vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox 
    executes to compromise Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks 
    may significantly impact additional products. Successful attacks of this vulnerability can result in 
    takeover of Oracle VM VirtualBox. (CVE-2020-14646, CVE-2020-14647, CVE-2020-14648, CVE-2020-14649, 
    CVE-2020-14650, CVE-2020-14673, CVE-2020-14674, CVE-2020-14675, CVE-2020-14676, CVE-2020-14677, 
    CVE-2020-14694, CVE-2020-14695, CVE-2020-14698, CVE-2020-14699, CVE-2020-14700, CVE-2020-14713)

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported 
    versions that are affected are Prior to 5.2.44, prior to 6.0.24 and prior to 6.1.12. Easily exploitable 
    vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox 
    executes to compromise Oracle VM VirtualBox. Successful attacks require human interaction from a person 
    other than the attacker. Successful attacks of this vulnerability can result in unauthorized creation, 
    deletion or modification access to critical data or all Oracle VM VirtualBox accessible data.
    (CVE-2020-14707, CVE-2020-14712)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14704");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14628");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version' : '5.2', 'fixed_version' : '5.2.44'},
  {'min_version' : '6.0', 'fixed_version' : '6.0.24'},
  {'min_version' : '6.1', 'fixed_version' : '6.1.12'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
