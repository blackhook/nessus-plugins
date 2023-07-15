#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78892);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2014-8354",
    "CVE-2014-8355",
    "CVE-2014-8561",
    "CVE-2014-8562"
  );
  script_bugtraq_id(
    70802,
    70830,
    70837,
    70839
  );

  script_name(english:"ImageMagick < 6.8.9-9 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ImageMagick prior to
version 6.8.9-9. It is, therefore, affected by the following
vulnerabilities :

  - An out-of-bounds read error exist in the function
    'CloneImage' within file 'image.c' that can allow
    application crashes or information disclosure.
    (CVE-2014-8354)

  - An out-of-bounds read error exist in the function
    'ReadPCXImage' within file 'coders/pcx.c' that can
    allow application crashes or information disclosure.
    (CVE-2014-8355)

  - An error exists in the function 'DeleteImageProfile'
    related to image processing that can allow denial of
    service attacks. (CVE-2014-8561)

  - An out-of-bounds read error exists in the 'ReadDCMImage'
    function within file 'coders/dcm.c' that can allow
    application crashes or information disclosure.
    (CVE-2014-8562)

  - An off-by-one error exists related to '8BIM' handling
    that can allow an attacker to have an unspecified
    impact.");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2014/10/29/5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.8.9-9 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'fixed_version' : '6.8.9-9'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
