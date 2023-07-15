#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156103);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-4104");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"0001-A-0650");

  script_name(english:"Apache Log4j 1.2 JMSAppender Remote Code Execution (CVE-2021-4104)");

  script_set_attribute(attribute:"synopsis", value:
"A package installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Log4j on the remote host is 1.2. It is, therefore, affected by a remote code execution
vulnerability when specifically configured to use JMSAppender.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/logging-log4j2/pull/608#issuecomment-990494126
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33485eac");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4104");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Log4j version 2.16.0 or later since 1.x is end of life.

Upgrading to the latest versions for Apache Log4j is highly recommended as intermediate 
versions / patches have known high severity vulnerabilities and the vendor is updating 
their advisories often as new research and knowledge about the impact of Log4j is 
discovered. Refer to https://logging.apache.org/log4j/2.x/security.html for the latest 
versions.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4104");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/15");

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

if (app_info['JMSAppender.class association'] == "Not Found")
  audit(AUDIT_OS_CONF_NOT_VULN, app, app_info.version);

var constraints = [{ 'min_version':'1.2.0', 'max_version':'1.2.17', 'fixed_version':'2.16.0' }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
