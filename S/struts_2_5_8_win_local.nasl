#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95887);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-8738");
  script_bugtraq_id(94657);

  script_name(english:"Apache Struts 2.5.x < 2.5.13 URLValidator Form Field Handling Remote DoS (S2-044)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework that is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.5.x prior to 2.5.13. It is, therefore, affected by a
denial of service vulnerability in the URLValidator class due to improper handling of user-supplied input to the form
field. An unauthenticated, remote attacker can exploit this, via a specially crafted URL, to overload server processes.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://cwiki.apache.org/confluence/display/WW/S2-044
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5c9df27");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.5.13 or later. Alternatively, apply the workaround referenced in the vendor 
advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");

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

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Apache Struts');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '2.5', 'fixed_version' : '2.5.13' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
