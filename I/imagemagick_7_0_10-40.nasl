#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144454);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-29599");
  script_xref(name:"IAVB", value:"2020-B-0076-S");

  script_name(english:"ImageMagick < 6.9.11-40 / 7.x < 7.0.10-40 -authenticate Option Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is prior to 6.9.11-40 or 7.x prior to 7.0.10-4.
It is, therefore, affected by a command injection vulnerability via the -authenticate option.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/discussions/2851");
  # https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7aef1910");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 6.9.11-40 or 7.0.10-40 or later.

Note that you may need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29599");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
app_info = vcf::imagemagick::get_app_info();

constraints = [
  { 'fixed_version':'6.9.11.40' },
  { 'min_version':'7.0.0.0', 'fixed_version':'7.0.10.40'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
