#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171167);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id("CVE-2022-44267", "CVE-2022-44268");
  script_xref(name:"IAVB", value:"2023-B-0006-S");

  script_name(english:"ImageMagick 7.1.0-49 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is 7.1.0-49. It is, therefore, affected
by the following vulnerabilities:

  - Denial of Service (DoS). When it parses a PNG image (e.g., for resize), the convert process could be 
    left waiting for stdin input. (CVE-2022-44267)
  
  - Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could 
  have embedded the content of an arbitrary file (if the magick binary has permissions to read it) (CVE-2022-44268)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.metabaseq.com/imagemagick-zero-days/");
  # https://github.com/ImageMagick/ImageMagick/commit/05673e63c919e61ffa1107804d1138c46547a475
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4314c6f2");
  # https://github.com/ImageMagick/ImageMagick/commit/05673e63c919e61ffa1107804d1138c46547a475
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4314c6f2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an unaffected version of ImageMagick.

Note that you may need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44268");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'equal' : '7.1.0.49', 'fixed_display' : 'See vendor advisory'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);