#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91818);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2016-5687", "CVE-2016-5688");
  script_bugtraq_id(91283);

  script_name(english:"ImageMagick 6.x < 6.9.4-3 / 7.x < 7.0.1-4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 6.x
prior to 6.9.4-3 or 7.x prior to 7.0.1-4. It is, therefore, affected
by the following vulnerabilities :

  - An out-of-bounds read error exists in the
    VerticalFilter() function in coders/dds.c due to
    improper handling of malformed DDS files. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted DDS file,
    to crash processes linked against the library, resulting
    in a denial of service condition. (CVE-2016-5687)

  - An overflow condition exists in the ReadWPGImage()
    function in coders/wpg.c due to improper validation of
    user-supplied input when handling WPG files. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted WPG file,
    to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2016-5688)

  - An invalid write error exists in the OpenPixelCache()
    function in MagickCore/cache.c due to improper handling
    of resources. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2016-5688)");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  # https://blog.fuzzing-project.org/46-Various-invalid-memory-accesses-in-ImageMagick-WPG,-DDS,-DCM.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b5f3426");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.4-3 / 7.0.1-4 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5687");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'min_version' : '6.0.0-0', 'fixed_version' : '6.9.4-3'},
  {'min_version' : '7.0.0-0', 'fixed_version' : '7.0.1-4'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
