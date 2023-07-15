#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97890);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2017-6502");
  script_bugtraq_id(96763);

  script_name(english:"ImageMagick 6.x < 6.9.7-9 / 7.x < 7.0.4-10 webp.c ReadWEBPImage() File Descriptor Exhaustion DoS");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 6.x
prior to 6.9.7-9 or 7.x prior to 7.0.4-10. It is, therefore, affected
by a denial of service vulnerability in the ReadWEBPImage() function
in coders/webp.c due to improper handling of WEBP files. An
unauthenticated, remote attacker can exploit this, by convincing a
user to open a specially crafted WEBP file, to exhaust available file
descriptors and cause a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/pull/382");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.7-9 / 7.0.4-10 or later. Note that
you may also need to manually uninstall the vulnerable version from
the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6502");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'min_version' : '6.0.0-0', 'fixed_version' : '6.9.7-9'},
  {'min_version' : '7.0.0-0', 'fixed_version' : '7.0.4-10'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
