##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148455);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/22");

  script_cve_id(
    "CVE-2021-21091",
    "CVE-2021-21092",
    "CVE-2021-21093",
    "CVE-2021-21094",
    "CVE-2021-21095",
    "CVE-2021-21096"
  );

  script_name(english:"Adobe Bridge 10.x < 10.1.2 / 11.x < 11.0.2 / 11.x < 11.0.2 Multiple Vulnerabilities (APSB21-23)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote macOS or Mac OS X host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote macOS or Mac OS X host is prior to 10.1.2 or 11.0.2 or 11.0.2. It
is, therefore, affected by multiple vulnerabilities as referenced in the apsb21-23 advisory. Note that Nessus has not
tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb21-23.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 10.1.2 or 11.0.2 or 11.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21095");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_bridge_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Bridge");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'Adobe Bridge');

constraints = [
  { 'min_version' : '10.0.0', 'max_version' : '10.1.1', 'fixed_version' : '10.1.2' },
  { 'min_version' : '10.0.0', 'max_version' : '10.1.1', 'fixed_version' : '11.0.2' },
  { 'min_version' : '11.0.0', 'max_version' : '11.0.1', 'fixed_version' : '11.0.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
