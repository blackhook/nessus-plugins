#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108379);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-4924");
  script_bugtraq_id(103395);

  script_name(english:"Adobe Dreamweaver < 18.1 OS Command Injection Vulnerability");
  script_summary(english:"Checks the version of Adobe Dreamweaver.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Dreamweaver installed on the remote Windows
host is affected by a OS command injeciton vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dreamweaver installed on the remote Windows
host is a version prior to 18.1. It is, therefore, affected
by an OS command injeciton vulnerability due to an unspecified flaw
within the URI handler. A remote attacker could inject arbitrary OS
commands and potentially execute code.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb18-07.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dreamweaver 18.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dreamweaver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dreamweaver_installed.nasl");
  script_require_keys("installed_sw/Adobe Dreamweaver");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::get_app_info(app:"Adobe Dreamweaver");

constraints = [{ "fixed_version" : "18.1" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
