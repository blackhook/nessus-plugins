#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164274);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/23");

  script_name(english:"Oracle Primavera Unifier Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of an Oracle Primavera 
Unifier application.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Oracle Primavera 
Unifier application running on the remote host is no longer supported per:

- End Of Support Date or End Of Life Date for Primavera Unifier and 
  Its Enabling Software Environment (Doc ID
  2526166.1)

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
# https://www.oracle.com/us/assets/lifetime-support-applications-069216.pdf 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdef07ac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Oracle Primavera that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_unifier");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier");

  exit(0);
}

include('vcf.inc');

var app = 'Oracle Primavera Unifier';

app_info = vcf::combined_get_app_info(app:app);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var now = get_kb_item("/tmp/start_time");
if (empty_or_null(now))
  now = int(gettimeofday());

# default constraint
var constraints = [ 
    { 'min_version' : '1.0', 'fixed_version' : '18.0', 'fixed_display':'18.x or later' }
  ];

if (now > 1656633600 && now < 1690848000 ) 
{
  constraints = [
    { 'min_version' : '1.0', 'fixed_version' : '18.0', 'fixed_display':'18.x or later' }
  ];
}
else if (now > 1690848000 && now < 1733011200 ) 
{
  constraints = [
    { 'min_version' : '1.0', 'fixed_version' : '19.0', 'fixed_display':'19.x or later' }
  ];
}
else if (now > 1733011200 && now < 1764547200 ) 
{
  constraints = [
    { 'min_version' : '1.0', 'fixed_version' : '20.0', 'fixed_display':'20.x or later' }
  ];
}
else if (now > 1764547200 && now < 1796083200 ) 
{
  constraints = [
    { 'min_version' : '1.0', 'fixed_version' : '21.0', 'fixed_display':'21.x or later' }
  ];
}

##
# Due to future changes, the VCF additions made for this plugin are being removed.
# The major elements of those changes have been moved, for the moment, to this plugin to maintain functionality while we 
# Remove the code to simplify the future upgrade process.
##

var matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints);
    if (vcf::is_error(matching_constraint)) return vcf::vcf_exit(1, matching_constraint.message);

if (!isnull(matching_constraint))
    {
      port = app_info.port;
      if (isnull(port)) port = 0;
      
      var version;

      if (isnull(app_info.display_version)) version = app_info.version;
      else version = app_info.display_version;

      register_unsupported_product(product_name:app_info.app , version:version, cpe_base:"cpe:/a:oracle:primavera_unifier");

      fix = matching_constraint.fixed_display;
      if (isnull(fix)) fix = matching_constraint.fixed_version;

      vcf::report_results(app_info:app_info, fix:fix, severity:SECURITY_HOLE);
    }
    # Audit
    else vcf::audit(app_info);