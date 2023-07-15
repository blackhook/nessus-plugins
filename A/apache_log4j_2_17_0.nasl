#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156183);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-45105");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"2021-A-0598");
  script_xref(name:"IAVA", value:"0001-A-0650");

  script_name(english:"Apache Log4j 2.x < 2.17.0 DoS");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Log4j on the remote host is 2.x < 2.3.1 / 2.13.2 / 2.17.0. It is, therefore, affected by 
a denial of service vulnerability. Apache Log4j2 versions 2.0-alpha1 through 2.16.0 did not protect from uncontrolled 
recursion from self-referential lookups. When the logging configuration uses a non-default Pattern Layout with a 
Context Lookup (for example, $${ctx:loginId}), attackers with control over Thread Context Map (MDC) input data can 
craft malicious input data that contains a recursive lookup, resulting in a StackOverflowError that will terminate 
the process.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-p6xc-xr62-6r2g");
  script_set_attribute(attribute:"see_also", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Log4j version 2.3.1, 2.12.3, 2.17.0 or later, or apply the vendor mitigation.

Upgrading to the latest versions for Apache Log4j is highly recommended as intermediate 
versions / patches have known high severity vulnerabilities and the vendor is updating 
their advisories often as new research and knowledge about the impact of Log4j is 
discovered. Refer to https://logging.apache.org/log4j/2.x/security.html for the latest 
versions.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45105");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:log4j");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_log4j_nix_installed.nbin", "apache_log4j_win_installed.nbin");
  script_require_keys("installed_sw/Apache Log4j");

  exit(0);
}

include('vcf.inc');

var app = 'Apache Log4j';

var app_info = vcf::get_app_info(app:app);

var constraints = [
  {'min_version':'2.0', 'fixed_version':'2.3.1', 'fixed_display': '2.3.1 / 2.17.0'},
  {'min_version':'2.4', 'fixed_version':'2.12.3', 'fixed_display': '2.12.3 / 2.17.0'},
  {'min_version':'2.13', 'fixed_version':'2.17.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
