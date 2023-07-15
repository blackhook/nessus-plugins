#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117461);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");
  script_xref(name:"IAVA", value:"0001-A-0515");

  script_name(english:"Apache Struts Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Apache Struts.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Apache Struts on
the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/struts1eol-announcement.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/struts23-eol-announcement");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache Struts that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"the product is no longer supported by vendor");
  
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include("vcf.inc");

app_info = vcf::combined_get_app_info(app:"Apache Struts");

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "1.0", "max_version" : "2.3.37", "fixed_version" : "2.5", "fixed_display":"2.5.x" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
