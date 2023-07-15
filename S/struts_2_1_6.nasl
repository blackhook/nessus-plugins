#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128766);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Apache Struts 2.0.x < 2.0.12 / 2.1.x < 2.1.6 Directory Traversal Vulnerability (S2-004)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework that is affected by a directory traversal 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.0.x prior to 2.0.12 or 2.1.x prior to 2.1.6. It is,
therefore, affected by a directory traversal vulnerability in FilterDispatcher (in 2.0) and DefaultStaticContentLoader
(in 2.1) due to inadequate restrictions. A remote, unauthenticated attacker can exploit this to traverse the directory
structure and download arbitrary files. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.0.12 / 2.1.6 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Directory Traversal");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Apache Struts');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.0.0', 'max_version' : '2.0.11.2', 'fixed_version' : '2.0.12' },
  { 'min_version' : '2.1.0', 'max_version' : '2.1.2', 'fixed_version' : '2.1.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
