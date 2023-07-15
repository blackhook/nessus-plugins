##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147412);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-21012",
    "CVE-2021-21013",
    "CVE-2021-21065",
    "CVE-2021-21066"
  );

  script_name(english:"Adobe Bridge 11.0 < 11.0.1 Multiple Vulnerabilities (APSB21-07)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote macOS or Mac OS X host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote macOS or Mac OS X host is prior to 11.0.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb21-07 advisory.

  - Magento versions 2.4.1 (and earlier), 2.4.0-p1 (and earlier) and 2.3.6 (and earlier) are vulnerable to an
    insecure direct object vulnerability (IDOR) in the checkout module. Successful exploitation could lead to
    sensitive information disclosure. (CVE-2021-21012)

  - Magento versions 2.4.1 (and earlier), 2.4.0-p1 (and earlier) and 2.3.6 (and earlier) are vulnerable to an
    insecure direct object vulnerability (IDOR) in the customer API module. Successful exploitation could lead
    to sensitive information disclosure. (CVE-2021-21013)

  - Adobe Bridge version 11.0 (and earlier) is affected by an out-of-bounds write vulnerability when parsing
    TTF files that could result in arbitrary code execution in the context of the current user. Exploitation
    of this issue requires user interaction in that a victim must open a malicious file. (CVE-2021-21065,
    CVE-2021-21066)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb21-07.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 11.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21066");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_bridge_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Bridge");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'Adobe Bridge');

constraints = [
  { 'fixed_version' : '11.0.1', 'equal' : '11.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
