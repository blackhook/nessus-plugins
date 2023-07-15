#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170137);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2023-21885");
  script_xref(name:"IAVA", value:"2023-A-0045-S");

  script_name(english:"Oracle VM VirtualBox Improper Authorization Windows (Jan 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an improper authorization vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of VirtualBox installed on the remote host is prior to 6.1.42 or prior to 7.0.6. It is, therefore, affected
by an improper authorization vulnerability as referenced in the Jan 2023 CPU advisory:

  - Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported
    versions that are affected are prior to 6.1.42 and prior to 7.0.6. Easily exploitable vulnerability allows
    low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise
    Oracle VM VirtualBox. While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Oracle VM VirtualBox accessible data. Note: Applies to Windows only.
    (CVE-2023-21885)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Jan 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21885");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_ports("installed_sw/Oracle VM VirtualBox");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle VM VirtualBox', win_local:TRUE);

var constraints = [
  {'min_version' : '6.1.0', 'fixed_version' : '6.1.42'},
  {'min_version' : '7.0.0', 'fixed_version' : '7.0.6'}
];


vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);