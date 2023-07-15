#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151134);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-20106");
  script_xref(name:"IAVB", value:"2021-B-0039");

  script_name(english:"Tenable Nessus Agent <= 8.2.5 Privilege Escalation (TNS-2021-13)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote system is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus agent running on the remote host is prior or equal to
8.2.5. It is, therefore, affected by a privilege escalation vulnerability which could allow a Nessus administrator user
to upload a specially crafted file that could lead to gaining administrator privileges on the Nessus host.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent version 8.3.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin", "nessus_agent_installed_macos.nbin", "nessus_agent_installed_linux.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Tenable Nessus Agent');

var constraints = [
  { 'max_version':'8.2.5', 'fixed_version':'8.3.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

