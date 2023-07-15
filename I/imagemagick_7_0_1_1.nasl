#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90892);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2016-3714",
    "CVE-2016-3715",
    "CVE-2016-3716",
    "CVE-2016-3717",
    "CVE-2016-3718"
  );
  script_bugtraq_id(
    89848,
    89849,
    89852,
    89861,
    89866
  );
  script_xref(name:"CERT", value:"250519");
  script_xref(name:"EDB-ID", value:"39767");
  script_xref(name:"EDB-ID", value:"39791");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"ImageMagick < 7.0.1-1 / 6.x < 6.9.3-10 Multiple Vulnerabilities (ImageTragick)");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is
prior to 7.0.1-1 or 6.x prior to 6.9.3-10. It is, therefore, affected
by the following vulnerabilities :

  - A remote code execution vulnerability, known as
    ImageTragick, exists due to a failure to properly filter
    shell characters in filenames passed to delegate
    commands. A remote attacker can exploit this, via
    specially crafted images, to inject shell commands and
    execute arbitrary code. (CVE-2016-3714)

  - An unspecified flaw exists in the 'ephemeral' pseudo
    protocol that allows an attacker to delete arbitrary
    files. (CVE-2016-3715)

  - An unspecified flaw exists in the 'ms' pseudo protocol
    that allows an attacker to move arbitrary files to
    arbitrary locations. (CVE-2016-3716)

  - An unspecified flaw exists in the 'label' pseudo
    protocol that allows an attacker, via a specially
    crafted image, to read arbitrary files. (CVE-2016-3717)

  - A server-side request forgery (SSRF) vulnerability
    exists due to an unspecified flaw related to request
    handling between a user and the server. A remote
    attacker can exploit this, via an MVG file with a
    specially crafted fill element, to bypass access
    restrictions and conduct host-based attacks.
    (CVE-2016-3718)");
  script_set_attribute(attribute:"see_also", value:"http://www.imagemagick.org/script/changelog.php");
  script_set_attribute(attribute:"see_also", value:"https://www.imagemagick.org/discourse-server/viewtopic.php?f=4&t=29588");
  script_set_attribute(attribute:"see_also", value:"https://imagetragick.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.1-1 / 6.9.3-10 or later.

Note that you may need to manually uninstall the vulnerable version
from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3714");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [
  {'min_version' : '6.0.0-0', 'fixed_version' : '6.9.3-10'},
  {'fixed_version' : '7.0.1-1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
