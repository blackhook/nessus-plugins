#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148711);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_name(english:"Tenable Nessus Network Monitor Unsupported Version Detection");
  script_summary(english:"Checks the NNM version.");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerability scanner application running on the remote host is no
longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Tenable Nessus Network Monitor (NNM) on the remote host is no
longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
    # https://www.tenable.com/downloads
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acfa0664");
  # https://tenable.my.salesforce.com/sfc/p/#300000000pZp/a/3a000000gPnK/Gu5PvUfKyV_gL0LdpNGgSdJ0PLKk15KPFcucY_BGlek
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1e381f2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Tenable NNM that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 Tenable Network Security, Inc.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

app_name = 'Tenable NNM';

app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '5.6.0' },
  { 'min_version': '5.7.0', 'fixed_version' : '5.9.0' }
];

var matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints);

if (!isnull(matching_constraint))
{
  fix = matching_constraint.fixed_display;
  if (isnull(fix)) fix = matching_constraint.fixed_version;

  register_unsupported_product(product_name:app_info.app, version:app_info.version, cpe_base:'tenable:nnm');

  vcf::report_results(app_info:app_info, fix:fix, severity:SECURITY_HOLE);
}
else vcf::audit(app_info);
