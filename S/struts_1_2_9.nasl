#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170824);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_cve_id("CVE-2006-1547");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/21");

  script_name(english:"Apache Struts 1.x < 1.2.9 Denial of Service (CVE-2006-1547)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 1.x prior to 1.2.9. It is, therefore, affected by a denial
of service vulnerability in the ActionForm class.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 1.2.9 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-1547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include("vcf.inc");

var app_info = vcf::combined_get_app_info(app:"Apache Struts");

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { "min_version" : "1.0", "fixed_version" : "1.2.9" },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
