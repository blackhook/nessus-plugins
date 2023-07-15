#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(59370);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2012-0259", "CVE-2012-0260", "CVE-2012-1798");
  script_bugtraq_id(52898);

  script_name(english:"ImageMagick < 6.7.6-3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ImageMagick earlier
than 6.7.6-3 and is, therefore, affected by the following
vulnerabilities :

  - An error exists in the function 'GetEXIFProperty' in
    the file 'magick/property.c' that can cause the
    application to crash when processing JPEG 'EXIF' data.
    (CVE-2012-0259)

  - An error exists in the function 'JPEGWarningHandler' in
    the file 'coders/jpeg.c' that can cause the application
    to consume large amounts of resources when handling JPEG
    'restart' markers. (CVE-2012-0260)

  - An error exists in the function 'TIFFGetEXIFProperties'
    in the file 'coders/tiff.c' that can cause the
    application crash when processing TIFF 'EXIF' 'IFD'
    data. (CVE-2012-1798)");
  script_set_attribute(attribute:"see_also", value:"http://www.cert.fi/en/reports/2012/vulnerability635606.html");
  # http://www.imagemagick.org/discourse-server/viewtopic.php?f=4&t=20629#p82689
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e13122e9");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.7.6-3 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0260");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'fixed_version' : '6.7.6-3'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
