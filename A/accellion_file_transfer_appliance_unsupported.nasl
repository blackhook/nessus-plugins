#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146927);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/28");

  script_name(english:"Accellion File Transfer Appliance Unsupported Version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is no longer supported by the vendor.");
  script_set_attribute(attribute:"description", value:
"The remote host is an Accellion File Transfer Appliance which is no longer supported by the vendor.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities.");
  # https://www.accellion.com/sites/default/files/resources/fta-eol.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6f8410d");
  script_set_attribute(attribute:"solution", value:"Upgrade to a more secure platform, kiteworks that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:accellion:secure_file_transfer_appliance");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("accellion_file_transfer_appliance_detect.nbin");
  script_require_keys("installed_sw/Accellion Secure File Transfer Appliance");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "Accellion Secure File Transfer Appliance";

if (!get_install_count(app_name:app_name))
  audit(AUDIT_WEB_APP_SUPPORTED, app_name);

port = get_http_port(default:443);
register_unsupported_product(product_name:app_name, cpe_class:CPE_CLASS_HARDWARE, cpe_base:"accellion:secure_file_transfer_appliance");

report = 'The remote host is running Accellion File Transfer Appliance (FTA) that is End of Life (EOL) on Apr 30th 2021.\n' +
         'It is recommended by Accellion that all customers upgrade to a more secure platform, kiteworks that is currently supported.';
security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
