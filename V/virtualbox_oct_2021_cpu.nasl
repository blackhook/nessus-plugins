#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154246);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id(
    "CVE-2021-2475",
    "CVE-2021-35540",
    "CVE-2021-35542",
    "CVE-2021-35545"
  );
  script_xref(name:"IAVA", value:"2021-A-0486-S");

  script_name(english:"Oracle VM VirtualBox (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VirtualBox installed on the remote host is prior to 6.1.28. It is, therefore, affected by multiple  
vulnerabilities as referenced in the October 2021 CPU advisory:

  - An easily exploitable vulnerability in the core component of Oracle VirtualBox that allows a highly
    privileged, authenticated attacker to impact confidentiality and availability. (CVE-2021-35545)

  - An easily exploitable vulnerability in the core component of Oracle VirtualBox that allows a low
    privileged, authenticated attacker to impact availability. (CVE-2021-35540)

  - An easily exploitable vulnerability in the core component of Oracle VirtualBox that allows a high
    privileged, authenticated attacker to compromise availability. (CVE-2021-35542)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html#AppendixOVIR");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35545");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl");
  script_require_keys("installed_sw/Oracle VM VirtualBox");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle VM VirtualBox', win_local:TRUE);

var constraints = [{ 'fixed_version' : '6.1.28' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
