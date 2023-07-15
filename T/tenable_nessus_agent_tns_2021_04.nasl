#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147895);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-20077", "CVE-2021-23840", "CVE-2021-23841");
  script_xref(name:"IAVB", value:"2021-B-0039");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Tenable Nessus Agent < 8.2.3 Multiple Vulnerabilities (TNS-2021-04)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote system is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"Nessus Agent versions 7.2.0 through 8.2.2 were found to inadvertently capture the IAM role security 
token on the local host during initial linking of the Nessus Agent when installed on an Amazon EC2 
instance. This could allow a privileged attacker to obtain the token.

Additionally, one third-party component (OpenSSL) was found to contain vulnerabilities, and updated 
versions have been made available by the provider. Nessus Agent version 8.2.3 will update OpenSSL to 1.1.1j.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-04-0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent version 8.2.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20077");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");

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

app_info = vcf::get_app_info(app:'Tenable Nessus Agent');

constraints = [
  {'min_version' : '7.2.0','fixed_version' : '8.2.3' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

