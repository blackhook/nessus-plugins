#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88714);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-5209", "CVE-2016-3090");
  script_bugtraq_id(82550, 85131);

  script_name(english:"Apache Struts 2.x < 2.3.24.1 Multiple Vulnerabilities (S2-026) (S2-027)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.x
prior to 2.3.24.1. It, therefore, is affected by multiple
vulnerabilities including a remote command execution vulnerability
and an open redirect vulnerability.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-026.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-027.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.24.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3090");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include("vcf.inc");

app_info = vcf::combined_get_app_info(app:"Apache Struts");

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.0.0", "max_version" : "2.3.24", "fixed_version" : "2.3.24.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
