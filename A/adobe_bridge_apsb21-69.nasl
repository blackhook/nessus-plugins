#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152630);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/18");

  script_cve_id(
    "CVE-2021-36049",
    "CVE-2021-36059",
    "CVE-2021-36067",
    "CVE-2021-36068",
    "CVE-2021-36069",
    "CVE-2021-36071",
    "CVE-2021-36072",
    "CVE-2021-36073",
    "CVE-2021-36074",
    "CVE-2021-36075",
    "CVE-2021-36076",
    "CVE-2021-36077",
    "CVE-2021-36078",
    "CVE-2021-36079",
    "CVE-2021-39816",
    "CVE-2021-39817"
  );

  script_name(english:"Adobe Bridge 11.x < 11.1.1 Multiple Vulnerabilities (APSB21-69)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Windows host is prior to 11.1.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the apsb21-69 advisory.

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2021-36072)

  - Access of Memory Location After End of Buffer (CWE-788) potentially leading to Arbitrary code execution
    (CVE-2021-36049, CVE-2021-36059, CVE-2021-36067, CVE-2021-36068, CVE-2021-36069, CVE-2021-36076,
    CVE-2021-36078)

  - Heap-based Buffer Overflow (CWE-122) potentially leading to Arbitrary code execution (CVE-2021-36073)

  - Out-of-bounds Read (CWE-125) potentially leading to Arbitrary code execution (CVE-2021-36079)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory leak (CVE-2021-36074)

  - Buffer Overflow (CWE-120) potentially leading to Arbitrary code execution (CVE-2021-36075)

  - Access of Memory Location After End of Buffer (CWE-788) potentially leading to Application denial-of-
    service (CVE-2021-36077)

  - Out-of-bounds Read (CWE-125) potentially leading to Arbitrary file system read (CVE-2021-36071)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/120.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/788.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb21-69.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 11.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36059");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120, 122, 125, 787, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_bridge_installed.nasl");
  script_require_keys("installed_sw/Adobe Bridge", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Bridge', win_local:TRUE);

var constraints = [
  { 'min_version' : '11.0.0', 'fixed_version' : '11.1.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
