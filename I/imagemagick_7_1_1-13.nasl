#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178031);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-3428");
  script_xref(name:"IAVB", value:"2023-B-0046");

  script_name(english:"ImageMagick 7.1.1-13 Heap-based Buffer Overflow DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by heap-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is 7.1.1-13 or prior. It is, therefore, affected
by heap-based buffer overflow vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2023-3428");
  # https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-fff3-4rp7-px97
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ea4db8d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an unaffected version of ImageMagick.

Note that you may need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3428");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/07");

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
  {'max_version' : '7.1.1.13', 'fixed_display' : 'See vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);