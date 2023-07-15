#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96447);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");


  script_name(english:"ImageMagick 7.x < 7.0.4-3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 7.x
prior to 7.0.4-3. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists in the
    ReadTIFFImage() function in tiff.c due to improper
    handling of TIFF files. An unauthenticated, remote
    attacker can exploit this, by convincing a user to open
    a specially crafted TIFF file, to cause a denial of
    service condition or the disclosure of memory contents.

  - A remote code execution vulnerability in the
    ReadPSDLayers() function in psd.c due to improper
    validation of PSB files. An unauthenticated, remote
    attacker can exploit this, by convincing a user to open
    a specially crafted PSD file, to cause a denial of
    service condition or the execution of arbitrary code.
");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/discourse-server/viewtopic.php?f=3&t=31161");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/347");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.4-3 or later. Note that you may
also need to manually uninstall the vulnerable version from the
system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Manual Analysis of the vulnerability");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'min_version' : '7.0.0-0', 'fixed_version' : '7.0.4-3'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
