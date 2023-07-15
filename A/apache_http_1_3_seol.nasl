#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171347);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/13");

  script_name(english:"Apache httpd SEoL (<= 1.3.x)");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Apache httpd is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, Apache httpd is less than or equal to 1.3.x. It is, therefore, no longer maintained by its
vendor or provider.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it may
contain security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://archive.apache.org/dist/httpd/Announcement1.3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache httpd that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_ports("installed_sw/Apache");

  exit(0);
}

include('ucf.inc');

var app = 'Apache';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { max_branch : '1.3', seol : 20100202 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
