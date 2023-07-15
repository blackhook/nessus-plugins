##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145015);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-21006");
  script_xref(name:"IAVA", value:"2021-A-0013-S");

  script_name(english:"Adobe Photoshop 22.x < 22.1.1 Vulnerability (APSB21-01)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote Windows host is prior to 22.1.1. It is, therefore, affected by a
vulnerability as referenced in the apsb21-01 advisory.

  - Adobe Photoshop version 22.1 (and earlier) is affected by a heap buffer overflow vulnerability when
    handling a specially crafted font file. Successful exploitation could lead to arbitrary code execution.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-21006)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb21-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 22.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21006");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Photoshop', win_local:TRUE);

constraints = [
  { 'min_version' : '22.0.0', 'max_version' : '22.1.0', 'fixed_version' : '22.1.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
