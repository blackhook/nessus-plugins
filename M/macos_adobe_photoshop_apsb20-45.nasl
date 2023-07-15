##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147620);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/11");

  script_cve_id(
    "CVE-2020-9683",
    "CVE-2020-9684",
    "CVE-2020-9685",
    "CVE-2020-9686",
    "CVE-2020-9687",
    "CVE-2020-9709"
  );

  script_name(english:"Adobe Photoshop CC 20.x < 20.0.10 / 21.x < 21.2.1 Multiple Vulnerabilities (macOS APSB20-45)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC or Photoshop installed on the remote macOS or Mac OS X host is prior to
20.0.10/21.2.1. It is, therefore, affected by multiple vulnerabilities as referenced in the apsb20-45 advisory.

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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9709");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_photoshop_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Photoshop");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'Adobe Photoshop');

constraints = [
  { 'min_version' : '20.0.0', 'max_version' : '20.0.9', 'fixed_version' : '20.0.10' },
  { 'min_version' : '21.0.0', 'max_version' : '21.2.0', 'fixed_version' : '21.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
