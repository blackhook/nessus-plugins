#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91764);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");


  script_name(english:"ImageMagick 7.x < 7.0.2-0 ReadSUNImage() Function SUN Image Handling DoS");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is
7.x prior to 7.0.2-0. It is, therefore, affected by a denial of
service vulnerability due to a flaw in the ReadSUNImage() function
in sun.c that is triggered during the handling of malformed SUN
images. An unauthenticated, remote attacker can exploit this, by
convincing a user to open a specially crafted SUN image, to crash
processes linked against the library, resulting in a denial of service
condition.");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/123");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.2-0 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Manual Analysis of the vulnerability");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 Tenable Network Security, Inc.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'min_version' : '7.0.0-0', 'fixed_version' : '7.0.2-0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
