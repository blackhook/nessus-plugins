#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174015);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/01");

  script_cve_id("CVE-2023-1289");
  script_xref(name:"IAVB", value:"2023-B-0020-S");

  script_name(english:"ImageMagick 7.1.1-0 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is 7.1.1-0. It is, therefore, affected
by a denial of service vulnerabilty where a specially created SVG file loads itself and causes a segmentation fault. 
This flaw allows a remote attacker to pass such a specially crafted SVG file leading to a segmentation fault, generating 
many trash files in '/tmp,' which can result in a denial of service. When ImageMagick crashes, it generates a lot of trash 
files. These trash files can be large if the SVG file contains many render actions. In a denial of service attack, if a 
remote attacker uploads an SVG file of size t, ImageMagick generates files of size 103*t. If an attacker uploads a 100M SVG, 
the server will generate about 10G.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-j96m-mjp6-99xr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30809205");
  # https://github.com/ImageMagick/ImageMagick/commit/c5b23cbf2119540725e6dc81f4deb25798ead6a4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13987312");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an unaffected version of ImageMagick.

Note that you may need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1289");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/07");

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
  {'max_version' : '6.9.1', 'fixed_display' : '7.1.1'},
  {'min_version' : '7.0.0', 'fixed_version' : '7.1.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);