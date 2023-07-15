#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72722);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2014-1958", "CVE-2014-2030");
  script_bugtraq_id(65478, 65563);
  script_xref(name:"EDB-ID", value:"31688");

  script_name(english:"ImageMagick < 6.8.8-5 Multiple PSD Handling Buffer Overflows");
  script_summary(english:"Checks the version of ImageMagick");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ImageMagick prior to
version 6.8.8-5.  It is, therefore, affected by the following
vulnerabilities :

  - A buffer overflow error exists related to PSD image
    file handling and the 'DecodePSDPixels' function.
    (CVE-2014-1958)

  - A buffer overflow error exists related to PDF image
    file handling and RLE decoding. (CVE-2014-2030)

Exploitation of these issues could result in a denial of service or
arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick 6.8.8-5 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2030");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'fixed_version' : '6.8.8-5'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
