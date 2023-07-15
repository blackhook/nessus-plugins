#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71461);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_xref(name:"IAVA", value:"0001-A-0604");

  script_name(english:"Tenable SecurityCenter Unsupported Version Detection");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Tenable
SecurityCenter.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable SecurityCenter
on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.tenable.com/downloads
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acfa0664");
  # https://tenable.my.salesforce.com/sfc/p/#300000000pZp/a/3a000000gPnK/Gu5PvUfKyV_gL0LdpNGgSdJ0PLKk15KPFcucY_BGlek
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1e381f2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Tenable SecurityCenter that is currently
supported.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter","installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('install_func.inc');
include('http.inc');
include('vcf_extras.inc');
include('vcf.inc');

## Checking if local detection occurred
var local_check_sc = get_kb_item('installed_sw/Tenable SecurityCenter');
if(!empty_or_null(local_check_sc))
{
  var app_info = vcf::tenable_sc::get_app_info();
}

## Checking if Remote detection occurred
var remote_check_sc = get_kb_item('installed_sw/SecurityCenter');
if(empty_or_null(local_check_sc) && !empty_or_null(remote_check_sc))
{
  var port = 0;
  var port = get_http_port(default:443, dont_exit:TRUE);
  var app_info = vcf::get_app_info(app:"SecurityCenter");
}
var constraints = [];
now = get_kb_item("/tmp/start_time");
if (empty_or_null(now))
  now = gettimeofday();

if (now  < 1659225600) # 4/30/22 - 7/31/22
{
  constraints =
  [
    {'min_version': '3.0.0', 'fixed_version' : '5.15.0', 'fixed_display':'5.15.x or later.'}
  ];
}
else if (now >= 1659225600 && now < 1667174400) # 7/31/22 - 10/31/22
  {
    constraints =
    [
      {'min_version': '3.0.0', 'fixed_version' : '5.16.0', 'fixed_display':'5.16.x or later.'}
    ];
  }
else if (now >= 1667174400 && now < 1672444800 ) # 10/31/22 - 12/31/22
  {
    constraints =
    [
      {'min_version': '3.0.0', 'fixed_version' : '5.17.0', 'fixed_display':'5.17.x or later.'}
    ];
  }
else if ( now >= 1672444800 && now < 1682812800 ) # 12/31/22 - 4/30/23
  {
    constraints =
    [
      {'min_version': '3.0.0', 'fixed_version' : '5.18.0', 'fixed_display':'5.18.x or later.'}
    ];
  }
else if ( now >= 1682812800 && now < 1690761600 ) # 4/30/23 - 7/31/23
  {
    constraints =
    [
      {'min_version': '3.0.0', 'fixed_version' : '5.19.0', 'fixed_display':'5.19.x or later.'}
    ];
  }
else if ( now >= 1690761600 && now < 1706659200 ) # 7/31/23 - 1/31/24
  {
    constraints =
    [
      {'min_version': '3.0.0', 'fixed_version' : '5.20.0', 'fixed_display':'5.20.x or later.'}
    ];
  }
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
