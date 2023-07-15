#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135586);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-2575",
    "CVE-2020-2741",
    "CVE-2020-2742",
    "CVE-2020-2743",
    "CVE-2020-2748",
    "CVE-2020-2758",
    "CVE-2020-2894",
    "CVE-2020-2902",
    "CVE-2020-2905",
    "CVE-2020-2907",
    "CVE-2020-2908",
    "CVE-2020-2909",
    "CVE-2020-2910",
    "CVE-2020-2911",
    "CVE-2020-2913",
    "CVE-2020-2914",
    "CVE-2020-2929",
    "CVE-2020-2951",
    "CVE-2020-2958",
    "CVE-2020-2959"
  );
  script_xref(name:"IAVA", value:"2020-A-0138-S");

  script_name(english:"Oracle VM VirtualBox (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle VM VirtualBox running on the remote host is 5.2.x prior to 5.2.40, 6.0.x prior to 6.0.20 or 6.1.x
prior to 6.1.6. It is, therefore, affected by multiple vulnerabilities as noted in the April 2019 Critical Patch
Update advisory. Note that Nessus has not tested for this issue buthas instead relied only on the 
application's self-reported version number:

  - An input-validation flaw exists within the processing of
    data sent to OHCI endpoints that could allow privilege
    escalation. (CVE-2020-2575)

  - An unspecified vulnerability exists in the Oracle
    Virtualization Core component. An authenticated,
    local attacker can exploit this issue, to compromise
    and takeover the Oracle VM VirtualBox. (CVE-2020-2742,
    CVE-2020-2758, CVE-2020-2894, CVE-2020-2905,
    CVE-2020-2908, CVE-2020-2902, CVE-2020-2907,
    CVE-2020-2911, CVE-2020-2913, CVE-2020-2914,
    CVE-2020-2929, CVE-2020-2958)

  - An unspecified vulnerability exists in the Oracle
    Virtualization Core component. An authenticated, local
    attacker can exploit this issue, for unauthorized access
    to critical data or complete access to all  Oracle VM
    VirtualBox accessible data. (CVE-2020-2741,
    CVE-2020-2743)

  - An unspecified vulnerability exists in the Oracle
    Virtualization Core component. An authenticated, local
    attacker can exploit this issue, for unauthorized read
    access to a subset of Oracle VM VirtualBox  accessible
    data. (CVE-2020-2748)

  - An unspecified vulnerability exists in the Oracle
    Virtualization Core component. An authenticated, local
    attacker can exploit this issue, for unauthorized
    creation, deletion or modification access to critical
    data or all Oracle VM VirtualBox accessible data.
    (CVE-2020-2910)

  - An unspecified vulnerability exists in the Oracle
    Virtualization Core component. An authenticated, local
    attacker can exploit this issue, for unauthorized
    ability to cause a partial denial of service (partial
    DOS) of Oracle VM VirtualBox. (CVE-2020-2909)

  - An unspecified vulnerability exists in the Oracle
    Virtualization Core component. An authenticated, local
    attacker can exploit this issue, for unauthorized
    ability to cause a hang or frequently repeatable crash
    (complete DOS) of Oracle VM VirtualBox. (CVE-2020-2959,
    CVE-2020-2951)");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.2.40, 6.0.20, 6.1.6 or later as referenced in the April 2020 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2929");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

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
  {'min_version' : '5.2', 'fixed_version' : '5.2.40'},
  {'min_version' : '6.0', 'fixed_version' : '6.0.20'},
  {'min_version' : '6.1', 'fixed_version' : '6.1.6'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
