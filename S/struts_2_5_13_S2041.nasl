#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129387);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-4465");
  script_bugtraq_id(91278);

  script_name(english:"Apache Struts 2.3.20 < 2.3.29 / 2.5.x < 2.5.13 Denial of Service Vulnerability (S2-041)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that uses a Java framework that is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote Windows host is 2.3.20 prior to 2.3.29 or 2.5.x < 2.5.13. It is,
therefore, affected by a denial of service vulnerability in URLValidator due to improper handling of form fields. An
unauthenticated, remote attacker can exploit this, via a crafted URL, to overload the server when performing validation
on the URL.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://cwiki.apache.org/confluence/display/WW/S2-041
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8420580c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.29 / 2.5.13  or later. Alternatively, apply the workarounds referenced in the
vendor advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/26");

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
  { 'min_version' : '2.3.20', 'max_version' : '2.3.28.1', 'fixed_display' : '2.3.29' },
  { 'min_version' : '2.5.0', 'fixed_version' : '2.5.13' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

