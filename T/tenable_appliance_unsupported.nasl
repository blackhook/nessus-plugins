#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136090);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/29");

  script_name(english:"Tenable Virtual Appliance Unsupported Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a Tenable Virtual Appliance which is no longer supported.");

  script_set_attribute(attribute:"description", value:
"The remote host is a Tenable Virtual Appliance which is no longer
supported as of April 30, 2020.
Lack of support implies that no security patches for the product will
be released by the vendor.  As a result, it is likely to contain
security vulnerabilities.");

  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/downloads/tenable-appliance");
  script_set_attribute(attribute:"solution", value:
"Replace Tenable Virtual Appliance with the latest Tenable Core.");
  
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:appliance");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_appliance_web_detect.nasl");
  script_require_keys("installed_sw/tenable_appliance");
  script_require_ports("Services/www", 8000);

  exit(0);
}

include("http.inc");
include("install_func.inc");

app_name = "Tenable Appliance";
install_name = 'tenable_appliance';

get_install_count(app_name:install_name, exit_if_zero:TRUE);

port = get_http_port(default:8000); 

install = get_single_install(
             app_name:install_name,
             port:port,
             exit_if_unknown_ver:FALSE
           );

if (empty_or_null(install)) audit(AUDIT_NOT_INST, app_name);

url = build_url(port:port, qs:install['path']);

eol_date = "2020-04-30";

register_unsupported_product(
  product_name : app_name,
  cpe_base     : "tenable:appliance",
  version      : install['version']
);

report = strcat( '\n  Product             : ',  app_name,
                 '\n  URL                 : ', url,
                 '\n  Installed version   : ', install['version'],
                 '\n  End of support date : ', eol_date);
   
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
