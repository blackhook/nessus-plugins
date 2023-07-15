#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78674);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/26");

  script_xref(name:"IAVA", value:"0001-A-0623");

  script_name(english:"WinZip Unsupported (Mac OS X)");
  script_summary(english:"Checks the version of WinZip.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
WinZip on the remote Mac OS X host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.winzip.com");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of WinZip that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winzip:winzip");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_winzip_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/WinZip");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
get_kb_item_or_exit("Host/MacOSX/Version");

appname = 'WinZip';

install = get_single_install(app_name:appname);
path = install['path'];
version = install['version'];

now = get_kb_item("Flatline/nowtime");
if (empty_or_null(now))
  now = gettimeofday();

# https://support.winzip.com/hc/en-us/articles/115011604028-End-of-Support-for-older-WinZip-application-versions
currently_supported = "6.0 - 8.x";
currently_unsupported_cutoff = "6.0.0";

if (now > 1614574800)  # March 2021
{
  currently_supported = "6.2 - 8.x";
  currently_unsupported_cutoff = "6.2.0";
}
if (now > 1625112000)  # July 2021
{
  currently_supported = "6.5 - 8.x";
  currently_unsupported_cutoff = "6.5.0";
}
if (now > 1654056000)  # June 2022
{
  currently_supported = "7.0 - 8.x";
  currently_unsupported_cutoff = "7.0.0";
}



if (ver_compare(ver:version, fix:currently_unsupported_cutoff, strict:FALSE) < 0)
{
  register_unsupported_product(product_name:appname,
                               cpe_base:"winzip:winzip", version:version);

  report =
    '\n  Path               : ' + path +
    '\n  Installed version  : ' + version +
    '\n  Supported versions : ' + currently_supported +
    '\n  EOL URL            : http://kb.winzip.com/kb/entry/132/' +
    '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_NOT_INST, "An unsupported version of "+appname);
