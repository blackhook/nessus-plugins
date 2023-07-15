#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171342);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/13");

  script_name(english:"Apache Tomcat SEoL (8.0.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Apache Tomcat is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Apache Tomcat is 8.0.x. It is, therefore, no longer maintained by its vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/tomcat-80-eol.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache Tomcat that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_ports("installed_sw/Apache Tomcat");

  exit(0);
}

include('ucf.inc');

var app = 'Apache Tomcat';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '8.0', min_branch : '8.0', seol : 20180630 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
