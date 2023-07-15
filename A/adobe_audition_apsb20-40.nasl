#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137645);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/06");

  script_cve_id("CVE-2020-9658", "CVE-2020-9659");
  script_xref(name:"IAVA", value:"2020-A-0270");

  script_name(english:"Adobe Audition < 13.0.7 Arbitrary Code Execution (APSB20-40)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Adobe Audition install on the
remote Windows host is potentially affected by an out-of-bounds write
vulnerability that could lead to arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/audition/apsb20-40.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Audition version 13.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9659");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:audition");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_audition_installed.nasl");
  script_require_keys("SMB/Adobe_Audition/installed");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Adobe Audition', win_local:TRUE);

constraints = [
  { 'fixed_version' : '13.0.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);