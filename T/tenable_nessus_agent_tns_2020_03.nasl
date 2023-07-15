#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137757);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-1551", "CVE-2020-1967");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Tenable Nessus Agent < 7.6.3 Third Party Vulnerability (OpenSSL) (TNS-2020-03)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote system is affected by a third party vulnerability
in OpenSSL");
  script_set_attribute(attribute:"description", value:
"Nessus Agent leverages third-party software to help provide underlying functionality. 
One of the third-party components (OpenSSL) was found to contain a multiple vulnerabilities, 
and updated versions have been made available by the providers.

Out of caution and in line with good practice, Tenable opted to upgrade the bundled library 
to address the potential impact of these issues in Nessus Agent. Nessus Agent 7.6.3 updates 
OpenSSL to version 1.1.1g to address the identified vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2020-03");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent version 7.6.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1551");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin", "nessus_agent_installed_macos.nbin", "nessus_agent_installed_linux.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Tenable Nessus Agent');

constraints = [
  {'fixed_version' : '7.6.3' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

