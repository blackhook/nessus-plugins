#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132962);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/27");

  script_cve_id(
    "CVE-2020-2674",
    "CVE-2020-2678",
    "CVE-2020-2681",
    "CVE-2020-2682",
    "CVE-2020-2689",
    "CVE-2020-2690",
    "CVE-2020-2691",
    "CVE-2020-2692",
    "CVE-2020-2693",
    "CVE-2020-2698",
    "CVE-2020-2701",
    "CVE-2020-2702",
    "CVE-2020-2703",
    "CVE-2020-2704",
    "CVE-2020-2705",
    "CVE-2020-2725",
    "CVE-2020-2726",
    "CVE-2020-2727"
  );
  script_xref(name:"IAVA", value:"2020-A-0022");

  script_name(english:"Oracle VM VirtualBox 5.2.x < 5.2.36 / 6.0.x < 6.0.16 / 6.1.x < 6.1.2 (Jan 2020 CPU)");
  script_summary(english:"Performs a version check on VirtualBox");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox running on the remote host is 5.2.x prior to 5.2.36, 6.0.x prior to 6.0.16 or 6.1.x
prior to 6.1.2. It is, therefore, affected by multiple vulnerabilities as noted in the January 2019 Critical Patch
Update advisory:

  - An unspecified vulnerability exists in the Oracle Virtualization Core component. An authenticated, local 
    attacker can exploit this issue, to compromise and takeover the Oracle VM VirtualBox. (CVE-2020-2674)

  - An unspecified vulnerability exists in the Oracle Virtualization Core component. An authenticated, local
    attacker can exploit this issue, for unauthorized creation, deletion or modification access to critical
    data or all Oracle VM VirtualBox accessible data as well as unauthorized read access to a subset of Oracle
    VM VirtualBox accessible data. (CVE-2020-2678)

  - A denial of service (DoS) vulnerability exists in the Oracle Virtualization Core component. An
    authenticated, local attacker can exploit this issue, to cause a hang or frequently repeatable crash
    (complete DoS) of Oracle VM VirtualBox. (CVE-2020-2703)");
  # https://www.oracle.com/security-alerts/cpujan2020.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc4414d8");
  # https://www.oracle.com/security-alerts/cpujan2020verbose.html#OVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cb6a420");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.2.36, 6.0.16, 6.1.2 or later as referenced in the January 2020 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version' : '5.2', 'fixed_version' : '5.2.36'},
  {'min_version' : '6.0', 'fixed_version' : '6.0.16'},
  {'min_version' : '6.1', 'fixed_version' : '6.1.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

