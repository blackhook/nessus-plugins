#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130055);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/17");

  script_cve_id(
    "CVE-2019-1547",
    "CVE-2019-2926",
    "CVE-2019-2944",
    "CVE-2019-2984",
    "CVE-2019-3002",
    "CVE-2019-3005",
    "CVE-2019-3017",
    "CVE-2019-3021",
    "CVE-2019-3026",
    "CVE-2019-3028",
    "CVE-2019-3031"
  );
  script_bugtraq_id(31765);
  script_xref(name:"IAVA", value:"2020-A-0022");

  script_name(english:"Oracle VM VirtualBox 5.2.x < 5.2.34 / 6.0.x < 6.0.14 (Oct 2019 CPU) (MacOSX)");
  script_summary(english:"Performs a version check");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox running on the remote Mac OS X host is
5.2.x prior to 5.2.34 or 6.0.x prior to 6.0.14. It is, therefore,
affected by multiple vulnerabilities as noted in the October 2019
Critical Patch Update advisory:

- A vulnerability exists in the Oracle VM VirtualBox product of Oracle Virtualization
  (component: Core) prior to 5.2.34 and prior to 6.0.14. An authenticated low privileged
  local attacker with logon to the infrastructure where Oracle VM VirtualBox can exploit
  the vulnerability to impact additional products or takeover The Oracle VM VirtualBox.
  (CVE-2019-3028)

- A vulnerability exists in the Oracle VM VirtualBox product of Oracle Virtualization
  (component: Core) prior to 5.2.34 and prior to 6.0.14. An authenticated high privileged
  local attacker with logon to the infrastructure where Oracle VM VirtualBox can exploit
  the vulnerability to impact additional products, cause a hang or frequently repeatable
  crash (complete DOS) of Oracle VM VirtualBox as well as unauthorized update, insert or
  delete access to some of Oracle VM VirtualBox accessible data and unauthorized read access
  to a subset of Oracle VM VirtualBox accessible data. (CVE-2019-2944)

- A denial of service (DoS) vulnerability exists in the Oracle VM VirtualBox product of
  Oracle Virtualization (component: Core) prior to 5.2.34 and prior to 6.0.14. An authenticated
  low privileged local attacker with logon to the infrastructure where Oracle VM VirtualBox can
  exploit the vulnerability to impact additional products or cause a hang or frequently repeatable
  crash (complete DOS) of Oracle VM VirtualBox. (CVE-2019-3021)


Please consult the CVRF details for the applicable CVEs for additional information.

Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b12e660");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.2.34 / 6.0.14 or later as
referenced in the October 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3028");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"agent", value:"all");


  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/VirtualBox");

  exit(0);
}

include('vcf.inc');

app  = 'VirtualBox';

app_info = vcf::get_app_info(app:app);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '5.2.0', 'fixed_version' : '5.2.34' },
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
