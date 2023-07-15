#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70739);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2013-4298");
  script_bugtraq_id(62080);

  script_name(english:"ImageMagick < 6.7.8-8 gif.c Memory Corruption");
  script_summary(english:"Checks the version of ImageMagick");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of ImageMagick prior to
version 6.7.8-8.  It is, therefore, affected by a memory corruption
vulnerability in 'gif.c' while processing GIF comments because a null
character is used to terminate comments.  Exploitation of this issue
could result in a denial of service or arbitrary code execution.  To fix
this issue, raw memory handling is replaced with a 'ConcatenateString'
function.");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"see_also", value:"https://bugs.launchpad.net/ubuntu/+source/imagemagick/+bug/1218248");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/discourse-server/viewtopic.php?f=3&t=23921");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2013/q3/532");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/discourse-server/viewtopic.php?f=4&t=24081");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick 6.7.8-8 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4298");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'fixed_version' : '6.7.8-8'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
