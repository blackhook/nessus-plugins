#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151827);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/31");

  script_cve_id("CVE-2021-36005", "CVE-2021-36006");
  script_xref(name:"IAVA", value:"2021-A-0338-S");

  script_name(english:"Adobe Photoshop 21.x < 21.2.10 / 22.x < 22.4.3 Multiple Vulnerabilities (macOS APSB21-63)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote macOS or Mac OS X host is prior to 21.2.10/22.4.3. It is,
therefore, affected by multiple vulnerabilities as referenced in the apsb21-63 advisory. Note that Nessus has not tested
for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/121.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb21-63.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop version 21.2.10/22.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36005");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 121);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '21.0.0', 'max_version' : '21.2.9', 'fixed_version' : '21.2.10' },
  { 'min_version' : '22.0.0', 'max_version' : '22.4.2', 'fixed_version' : '22.4.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
