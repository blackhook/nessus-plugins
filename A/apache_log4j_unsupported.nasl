#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156032);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_xref(name:"IAVA", value:"0001-A-0650");

  script_name(english:"Apache Log4j Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"A logging library running on the remote host is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of Apache Log4j on the remote host is no longer
supported. Log4j reached its end of life prior to 2016.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is
likely to contain security vulnerabilities.");
  # https://blogs.apache.org/foundation/entry/apache_logging_services_project_announces
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59f655a2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache Log4j that is currently supported.

Upgrading to the latest versions for Apache Log4j is highly recommended as intermediate 
versions / patches have known high severity vulnerabilities and the vendor is updating 
their advisories often as new research and knowledge about the impact of Log4j is 
discovered. Refer to https://logging.apache.org/log4j/2.x/security.html for the latest 
versions.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported software.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:log4j");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_log4j_win_installed.nbin", "apache_log4j_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Log4j");

  exit(0);
}

include('vcf.inc');

var app = 'Apache Log4j';
var win_local = FALSE;

if (get_kb_item('SMB/Registry/Enumerated'))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:app, win_local:win_local);

var ver  = app_info['version'];
var path = app_info['path'];
var port = app_info['port'];

if (!port)
  port = 0;

# Versions < 2 are EOL, so audit if version >= 2
if (ver_compare(ver:ver, fix:'2.0', strict:FALSE) >= 0)
  vcf::audit(app_info);

register_unsupported_product(
  product_name : app,
  cpe_base     : 'apache:log4j',
  cpe_class    : CPE_CLASS_APPLICATION,
  is_custom_cpe: FALSE,
  version      : ver
);

var report = strcat(
  '\n  Path              : ', path,
  '\n  Installed version : ', ver,
  '\n');

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
