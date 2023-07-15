#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159378);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/03");

  script_cve_id("CVE-2022-0778");

  script_name(english:"Tenable Nessus Agent < 8.3.3 / 10.x < 10.1.3 Third-Party Vulnerability (TNS-2022-07)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote system is affected by a third party vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus agent running on the remote host is prior to 8.3.3 or 10.x
prior to 10.1.3. It is, therefore, affected by a vulnerability in a third-party library.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent version 8.3.3 or 10.1.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0778");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin", "nessus_agent_installed_macos.nbin", "nessus_agent_installed_linux.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Tenable Nessus Agent');

var constraints = [
  { 'min_version':'8.0.0',  'fixed_version':'8.3.3'  },
  { 'min_version':'10.0.0', 'fixed_version':'10.1.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);