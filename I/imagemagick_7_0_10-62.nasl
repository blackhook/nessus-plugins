##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147894);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/24");

  script_cve_id("CVE-2021-20245", "CVE-2021-20246");
  script_xref(name:"IAVB", value:"2021-B-0017-S");

  script_name(english:"ImageMagick < 6.9.11-62, 7.0.0 < 7.0.10-62 Divide By Zero");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected Divide By Zero vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is prior to 6.9.11-62 or 7.0.x prior to 7.0.10-62.
It is, therefore, affected by following vulnerablities.

  - A flaw was found in ImageMagick in coders/webp.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of math division by zero. The highest threat from
    this vulnerability is to system availability. (CVE-2021-20245)

  - A flaw was found in ImageMagick in MagickCore/resample.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The highest
    threat from this vulnerability is to system availability. (CVE-2021-20246)");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/3176");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.11-62 or 7.0.10-62 or later.

Note that you may need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
app_info = vcf::imagemagick::get_app_info();

constraints = [
  {'fixed_version' : '6.9.11.62'},
  {'min_version' : '7.0.0',  'fixed_version' : '7.0.10.62'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
