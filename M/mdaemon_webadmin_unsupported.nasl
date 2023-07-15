#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100596);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVA", value:"0001-A-0513");

  script_name(english:"Alt-N MDaemon WebAdmin Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of MDaemon WebAdmin.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
MDaemon WebAdmin running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that MDaemon WebAdmin is bundled with MDaemon.");
  script_set_attribute(attribute:"see_also", value:"https://www.altn.com/Support/#SupportedProducts_EOL");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of MDaemon that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:altn:mdaemon");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:altn:mdaemon_webconfig");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2020 Tenable Network Security, Inc.");

  script_dependencies("mdaemon_webadmin_detect.nbin");
  script_require_ports("installed_sw/MDaemon WebAdmin");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app        = 'MDaemon WebAdmin';
cutoff_ver = "12.5.9"; 
eol_date   = "2017/05/31";
eol_url    = "https://www.altn.com/Support/#SupportedProducts_EOL";
supported  = "13.0 or later";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:1000);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install["version"];
dir     = install["path"];
url     = build_url(port:port, qs:dir);

if (ver_compare(ver:version, fix:cutoff_ver, strict:FALSE) > 0)
  audit(AUDIT_SUPPORTED, app, version, url);

register_unsupported_product(product_name:app, cpe_base:"altn:mdaemon", version:version);

security_report_v4(
  port: port,
  severity: SECURITY_HOLE,
  extra:
    '\n  Product             : ' + app +
    '\n  URL                 : ' + url +
    '\n  Installed version   : ' + version +
    '\n  End of support date : ' + eol_date +
    '\n  End of support URL  : ' + eol_url +
    '\n  Supported versions  : ' + supported +
    '\n'
);
