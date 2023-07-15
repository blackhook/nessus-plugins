#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125882);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-1559");
  script_bugtraq_id(107174);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Tenable Nessus Agent < 7.4.0 Third Party Vulnerability (OpenSSL) (TNS-2019-03)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote system is affected by a third party vulnerability
in OpenSSL");
  script_set_attribute(attribute:"description", value:
"The version of Nessus Agent installed on the remote Windows host is
prior to 7.4.0. It is, therefore, affected by one of the third-party
components (OpenSSL) was found to contain a single vulnerability, and
updated versions have been made available by the providers.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2019-03");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent version 7.4.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin", "nessus_agent_installed_macos.nbin", "nessus_agent_installed_linux.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Tenable Nessus Agent');

constraints = [
  { 'max_version' : '7.3.2', 'fixed_version' : '7.4.0' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
