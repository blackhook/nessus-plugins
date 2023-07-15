#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79860);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-7809", "CVE-2015-5169");
  script_bugtraq_id(71548, 76625);

  script_name(english:"Apache Struts 2 Multiple Vulnerabilities (S2-023) (S2-025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that uses a Java
framework that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server is using a version of Struts 2 that is affected
by multiple vulnerabilities :

  - A cross-site request forgery vulnerability exists due to
    the token generator failing to adequately randomize the
    token values. An attacker can exploit this issue by
    extracting a token from a form and then predicting the
    next token value that will be used to secure form
    submissions. By convincing a victim to visit a specially
    crafted form, the predicted token value can be used to
    force an action for a logged in user. Note that this
    vulnerability can only be exploited when the <s:token/>
    tag is used within a form. (CVE-2014-7809)

  - A cross-site scripting vulnerability exists due to
    improper validation of input passed via the 'Problem
    Report' screen when using debug mode. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in the context of a user's browser session.
    (CVE-2015-5169)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-023.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/s2-025.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/WW-4423");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.20 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7809");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/10");

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
include("vcf.inc");

app_info = vcf::combined_get_app_info(app:"Apache Struts");

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.0.0", "max_version" : "2.3.16.3", "fixed_version" : "2.3.20" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE, xsrf:TRUE});
