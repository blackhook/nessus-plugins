#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97892);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2017-6497", "CVE-2017-6499", "CVE-2017-6501");
  script_bugtraq_id(96589, 96590, 96594);

  script_name(english:"ImageMagick 6.x < 6.9.7-8 / 7.x < 7.0.4-8 Multiple DoS");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 6.x
prior to 6.9.7-8 or 7.x prior to 7.0.4-8. It is, therefore, affected
by multiple denial of service vulnerabilities :

  - A NULL pointer dereference flaw exists in the
    ReadPSDChannel() function in coders/psd.c due to
    improper handling of PSD files. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to open a specially crafted PSD file, to cause a denial
    of service condition. (CVE-2017-6497)

  - A flaw exists in Magick++/lib/Exception.cpp due to
    improper handling of nested exceptions. An
    unauthenticated, remote attacker can exploit this to
    cause the application to consume excessive resources,
    resulting in a denial of service condition.
    (CVE-2017-6499)

  - A NULL pointer dereference flaw exists in the
    ReadXCFImage() function in coders/xcf.c due to improper
    handling of XCF files. An unauthenticated, remote
    attacker can exploit this, by convincing a user to open
    a specially crafted XCF file, to cause a denial of
    service condition. (CVE-2017-6501)");
  # https://github.com/ImageMagick/ImageMagick/commit/7f2dc7a1afc067d0c89f12c82bcdec0445fb1b94
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?764ccdd1");
  # https://github.com/ImageMagick/ImageMagick/commit/d31fec57e9dfb0516deead2053a856e3c71e9751
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47ca94a9");
  # https://github.com/ImageMagick/ImageMagick/commit/3358f060fc182551822576b2c0a8850faab5d543
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?762e4c8b");
  # https://www.imagemagick.org/discourse-server/viewtopic.php?f=23&p=142634
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07868ede");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.7-8 / 7.0.4-8 or later. Note that
you may also need to manually uninstall the vulnerable version from
the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6497");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'min_version' : '6.0.0-0', 'fixed_version' : '6.9.7-8'},
  {'min_version' : '7.0.0-0', 'fixed_version' : '7.0.4-8'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
