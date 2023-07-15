##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144979);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-21007");
  script_xref(name:"IAVA", value:"2021-A-0014-S");

  script_name(english:"Adobe Illustrator CC < 25.1 Arbitrary code execution (APSB21-02)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator CC on the remote Windows hosts is prior to 25.1. It is, therefore, affected by an
uncontrolled search path element that could result in arbitrary code execution in the context of the current user.
Exploitation of this issue requires user interaction in that a victim must open a malicious file.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://helpx.adobe.com/security/products/illustrator/apsb21-02.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdf576ac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator CC 25.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21007");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");

  exit(0);
}


include('vcf.inc');

app_info = vcf::get_app_info(app:'Adobe Illustrator', win_local:TRUE);

constraints = [
  { 'fixed_version': '25.1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
