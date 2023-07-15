#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164574);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2020-11022", "CVE-2020-11023");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.19)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.19. It is, therefore, affected by multiple vulnerabilities
as referenced in the NXSA-AOS-5.19 advisory.

  - In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources -
    even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and
    others) may execute untrusted code. This problem is patched in jQuery 3.5.0. (CVE-2020-11022)

  - In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option>
    elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods
    (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.
    (CVE-2020-11023)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.19
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?464d146f");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.19', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.19 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.19', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.19 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
