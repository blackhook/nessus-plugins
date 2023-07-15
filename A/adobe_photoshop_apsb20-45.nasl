##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(138891);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/18");

  script_cve_id(
    "CVE-2020-9683",
    "CVE-2020-9684",
    "CVE-2020-9685",
    "CVE-2020-9686",
    "CVE-2020-9687",
    "CVE-2020-9709"
  );
  script_xref(name:"IAVA", value:"2020-A-0332-S");

  script_name(english:"Adobe Photoshop CC 20.x < 20.0.10 / 21.x < 21.2.1 Multiple Vulnerabilities (APSB20-45)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC or Photoshop installed on the remote Windows host is prior to 20.0.10/21.2.1. It is,
therefore, affected by multiple vulnerabilities as referenced in the apsb20-45 advisory.

  - Adobe Photoshop versions Photoshop CC 2019, and Photoshop 2020 have an out-of-bounds read vulnerability.
    Successful exploitation could lead to arbitrary code execution. (CVE-2020-9683, CVE-2020-9686)

  - Adobe Photoshop versions Photoshop CC 2019, and Photoshop 2020 have an out-of-bounds write vulnerability.
    Successful exploitation could lead to arbitrary code execution . (CVE-2020-9684, CVE-2020-9685,
    CVE-2020-9687)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb20-45.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 20.0.10/21.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9684");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Photoshop', win_local:TRUE);

constraints = [
  { 'min_version' : '20.0.0', 'max_version' : '20.0.9', 'fixed_version' : '20.0.10' },
  { 'min_version' : '21.0.0', 'max_version' : '21.2.0', 'fixed_version' : '21.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
