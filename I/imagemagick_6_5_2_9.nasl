#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38951);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2009-1882");
  script_bugtraq_id(35111);
  script_xref(name:"Secunia", value:"35216");

  script_name(english:"ImageMagick < 6.5.2-9 magick/xwindow.c XMakeImage() Function TIFF File Handling Overflow");
  script_summary(english:"Checks the version of ImageMagick");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
an integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ImageMagick earlier
than 6.5.2-9.  Such versions reportedly fail to properly handle
malformed 'TIFF' files in the 'XMakeImage()' function.  If an attacker
can trick a user on the remote host into opening a specially crafted
file using the affected application, he can leverage this flaw to
execute arbitrary code on the remote host subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://mirror1.smudge-it.co.uk/imagemagick/www/changelog.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.5.2-9 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1882");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");
  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");
  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'fixed_version' : '6.5.2-9'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
