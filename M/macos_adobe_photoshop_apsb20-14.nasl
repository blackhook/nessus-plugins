##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(134763);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id(
    "CVE-2020-3770",
    "CVE-2020-3771",
    "CVE-2020-3772",
    "CVE-2020-3773",
    "CVE-2020-3774",
    "CVE-2020-3775",
    "CVE-2020-3776",
    "CVE-2020-3777",
    "CVE-2020-3778",
    "CVE-2020-3779",
    "CVE-2020-3780",
    "CVE-2020-3781",
    "CVE-2020-3782",
    "CVE-2020-3783",
    "CVE-2020-3784",
    "CVE-2020-3785",
    "CVE-2020-3786",
    "CVE-2020-3787",
    "CVE-2020-3788",
    "CVE-2020-3789",
    "CVE-2020-3790",
    "CVE-2020-3791"
  );
  script_xref(name:"IAVA", value:"2020-A-0113-S");

  script_name(english:"Adobe Photoshop CC 20.x < 20.0.9 / 21.x < 21.1.1 Multiple Vulnerabilities (macOS APSB20-14)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC or Photoshop installed on the remote macOS or Mac OS X host is prior to 20.0.9/21.1.1.
It is, therefore, affected by multiple vulnerabilities as referenced in the apsb20-14 advisory.

  - Adobe Photoshop CC 2019 versions 20.0.8 and earlier, and Photoshop 2020 versions 21.1 and earlier have a
    buffer errors vulnerability. Successful exploitation could lead to arbitrary code execution.
    (CVE-2020-3770, CVE-2020-3772, CVE-2020-3774, CVE-2020-3775, CVE-2020-3776, CVE-2020-3780)

  - Adobe Photoshop CC 2019 versions 20.0.8 and earlier, and Photoshop 2020 versions 21.1 and earlier have an
    out-of-bounds read vulnerability. Successful exploitation could lead to information disclosure.
    (CVE-2020-3771, CVE-2020-3777, CVE-2020-3781, CVE-2020-3782, CVE-2020-3791)

  - Adobe Photoshop CC 2019 versions 20.0.8 and earlier, and Photoshop 2020 versions 21.1 and earlier have an
    out-of-bounds write vulnerability. Successful exploitation could lead to arbitrary code execution.
    (CVE-2020-3773, CVE-2020-3779)

  - Adobe Photoshop versions Photoshop CC 2019, and Photoshop 2020 have an out-of-bounds read vulnerability.
    Successful exploitation could lead to information disclosure. (CVE-2020-3778)

  - Adobe Photoshop CC 2019 versions 20.0.8 and earlier, and Photoshop 2020 versions 21.1 and earlier have a
    heap corruption vulnerability. Successful exploitation could lead to arbitrary code execution.
    (CVE-2020-3783)

  - Adobe Photoshop CC 2019 versions 20.0.8 and earlier, and Photoshop 2020 versions 21.1 and earlier have a
    memory corruption vulnerability. Successful exploitation could lead to arbitrary code execution.
    (CVE-2020-3784, CVE-2020-3785, CVE-2020-3786, CVE-2020-3787, CVE-2020-3788, CVE-2020-3789, CVE-2020-3790)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb20-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 20.0.9/21.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3789");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_photoshop_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Photoshop");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'Adobe Photoshop');

constraints = [
  { 'min_version' : '20.0.0', 'max_version' : '20.0.8', 'fixed_version' : '20.0.9' },
  { 'min_version' : '21.0.0', 'max_version' : '21.1.0', 'fixed_version' : '21.1.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
