##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144052);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-24447");
  script_xref(name:"IAVA", value:"2020-A-0569-S");

  script_name(english:"Adobe Lightroom Classic < 10.1 Arbitrary Code Execution (APSB20-74)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Lightroom Classic installed on the remote Windows host is prior to 10.1. It is, therefore, 
affected by an uncontrolled search path element vulnerability. Successful exploitation could lead to a arbitrary code 
execution on an affected host.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version");
  # https://helpx.adobe.com/security/products/lightroom/apsb20-74.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e3e4935");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Lightroom Classic 10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24447");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:lightroom");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_lightroom_classic_installed.nbin");
  script_require_keys("installed_sw/Adobe Lightroom Classic");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Lightroom Classic', win_local:TRUE);
constraints = [{'fixed_version':'10.1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
