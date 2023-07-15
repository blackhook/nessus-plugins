#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164912);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id("CVE-2022-2719");
  script_xref(name:"IAVB", value:"2022-B-0032-S");

  script_name(english:"ImageMagick < 7.1.0-30 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is prior 7.1.0-30. It is, therefore, affected
by a denial of service vulnerability. A crafted file can trigger an assertion failure when a call to WriteImage
is made with a NULL image list.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2116537");
  # https://github.com/ImageMagick/ImageMagick/commit/716496e6df0add89e9679d6da9c0afca814cfe49
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5080d6f5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.1.0-30 or later.

Note that you may need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2719");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'fixed_version' : '7.1.0.30'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
