#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150715);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"SonicWall Secure Remote Access (SRA) Unsupported Version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is no longer supported by the vendor.");
  script_set_attribute(attribute:"description", value:
"The remote host is a SonicWall Secure Remote Access (SRA) which is no longer supported by the vendor.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities.");
  # https://www.sonicwall.com/support/product-lifecycle-tables/sonicwall-secure-mobile-access/hardware/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?914bc86e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a SonicWall Secure Mobile Access (SMA) device that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:remote_access_firmware");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sma_web_detect.nbin");
  script_require_keys("installed_sw/SonicWall Secure Remote Access");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('install_func.inc');

app_name = 'SonicWall Secure Remote Access';

if (!get_install_count(app_name:app_name))
  audit(AUDIT_HOST_NOT, app_name);

register_unsupported_product(
  product_name : app_name,
  cpe_class    : CPE_CLASS_OS,
  cpe_base     : 'sonicwall:remote_access_firmware'
);

report = strcat('The remote host is running ', app_name, ' that is no longer supported by the vendor.');

port = get_http_port(default:443, embedded:TRUE);

get_single_install(app_name:app_name, port:port);

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
