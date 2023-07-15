#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73944);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-0116");
  script_bugtraq_id(67218);

  script_name(english:"Apache Struts 2 CookieInterceptor Unspecified Security Bypass (S2-022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that uses a Java framework that is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web application appears to use Struts 2, a Java based web application framework. The version of Struts 2 in
use is affected by a security bypass vulnerability due to a flaw with CookieInterceptor. A remote, unauthenticated
attacker can exploit this issue to manipulate the ClassLoader and modify a session state to bypass security
restrictions.

Note that this vulnerability can only be exploited when a wildcard
character is used to configure the 'cookiesName' value.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://cwiki.apache.org/confluence/display/WW/S2-022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9aff5358");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.20 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0116");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}
include('vcf.inc');
app_info = vcf::combined_get_app_info(app:'Apache Struts');
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.0.0', 'max_version' : '2.3.16.3', 'fixed_version' : '2.3.20' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
