#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137905);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/25");

  script_cve_id("CVE-2020-9617");
  script_xref(name:"IAVA", value:"2020-A-0226-S");

  script_name(english:"Adobe Premiere Rush <= 1.5.8 Out-Of-Bounds Read (APSB20-29)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Premiere Rush installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Rush installed on the remote Windows host is version less than or equal to 1.5.8. It is,
therefore, affected by an out-of-bounds read vulnerability that could lead to information disclosure.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://helpx.adobe.com/security/products/premiere_rush/apsb20-29.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80fb0d4e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Premiere Rush version 1.5.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_rush");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_rush_installed.nasl");
  script_require_keys("installed_sw/Adobe Premiere Rush", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Premiere Rush', win_local:TRUE);

constraints = [
  { 'fixed_version' : '1.5.9', 'fixed_display' : '1.5.12' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
