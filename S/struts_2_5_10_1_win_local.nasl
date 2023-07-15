#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97576);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5638");
  script_bugtraq_id(96729);
  script_xref(name:"CERT", value:"834067");
  script_xref(name:"EDB-ID", value:"41570");
  script_xref(name:"EDB-ID", value:"41614");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Apache Struts 2.3.5 - 2.3.31 / 2.5.x < 2.5.10.1 Jakarta Multipart Parser RCE (S2-045) (S2-046)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web application that uses a Java framework
that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.3.5
through 2.3.31 or else 2.5.x prior to 2.5.10.1. It is, therefore,
affected by a remote code execution vulnerability in the Jakarta
Multipart parser due to improper handling of the Content-Type,
Content-Disposition, and Content-Length headers. An unauthenticated,
remote attacker can exploit this, via a specially crafted header value
in the HTTP request, to potentially execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html");
  # https://threatpost.com/apache-struts-2-exploits-installing-cerber-ransomware/124844/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77e9c654");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.5.10.1");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.3.32");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-045");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-046");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.32 / 2.5.10.1 or later.
Alternatively, apply the workaround referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5638");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Jakarta Multipart Parser OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include("vcf.inc");

app_info = vcf::combined_get_app_info(app:"Apache Struts");

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "2.3.5", "max_version" : "2.3.31", "fixed_version" : "2.3.32" },
  { "min_version" : "2.5", "max_version" : "2.5.10", "fixed_version" : "2.5.10.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

