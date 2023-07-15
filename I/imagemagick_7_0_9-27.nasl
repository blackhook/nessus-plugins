#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139224);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/18");

  script_cve_id("CVE-2020-13902");
  script_xref(name:"IAVB", value:"2020-B-0042-S");

  script_name(english:"ImageMagick 7.0.9-27 < 7.0.10-17 Heap-buffer-overflow in BlobToStringInfo");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
Heap-buffer-overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is 7.0.9-27 prior to 7.0.10-17  It is, therefore,
affected by a heap-based buffer over-read vulnerability due to a flaw in BlobToStringInfo in MagickCore/string.c
during TIFF image decoding.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=20920");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.10-17 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
app_info = vcf::imagemagick::get_app_info();

constraints = [
  { 'min_version':'7.0.9.27',
    'fixed_version' : '7.0.10.17'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
