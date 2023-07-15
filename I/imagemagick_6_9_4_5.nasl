#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91819);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2016-5689",
    "CVE-2016-5690",
    "CVE-2016-5691",
    "CVE-2016-10066",
    "CVE-2016-10067",
    "CVE-2016-10069"
  );
  script_bugtraq_id(91283);

  script_name(english:"ImageMagick 6.x < 6.9.4-5 / 7.x < 7.0.1-7 Multiple DoS");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 6.x
prior to 6.9.4-5 or 7.x prior to 7.0.1-7. It is, therefore, affected
by multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the DCM
    reader due to a NULL pointer dereference flaw that is
    triggered during the handling of photometric
    interpretation or the handling of frames. An
    unauthenticated, remote attacker can exploit this to
    crash processes linked against the library.
    (CVE-2016-5689)

  - A denial of service vulnerability exists in the DCM
    reader due to improper computation of the pixel scaling
    table. An unauthenticated, remote attacker can exploit
    this to crash processes linked against the library.
    (CVE-2016-5690)

  - A denial of service vulnerability exists in the DCM
    reader due to improper validation of pixel.red,
    pixel,green, and pixel.blue. An unauthenticated, remote
    attacker can exploit this to crash processes linked
    against the library. (CVE-2016-5691)

  - Multiple denial of service vulnerabilities exist in
    multiple functions in viff.c due to improper handling of
    a saturation of exceptions. An unauthenticated, remote
    attacker can exploit these issues to crash processes
    linked against the library. (CVE-2016-10066,
    CVE-2016-10067)

  - A denial of service vulnerability exists in the
    ThrowReaderException() function in mat.c due to improper
    handling of frame numbers in a crafted MAT file. An
    unauthenticated, remote attacker can exploit this to
    crash processes linked against the library.
    (CVE-2016-10069)");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  # https://blog.fuzzing-project.org/46-Various-invalid-memory-accesses-in-ImageMagick-WPG,-DDS,-DCM.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b5f3426");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.4-5 / 7.0.1-7 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5691");

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
  {'min_version' : '6.0.0-0', 'fixed_version' : '6.9.4-5'},
  {'min_version' : '7.0.0-0', 'fixed_version' : '7.0.1-7'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
