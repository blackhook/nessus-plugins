#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154426);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/23");

  script_cve_id(
    "CVE-2021-40750",
    "CVE-2021-42533",
    "CVE-2021-42719",
    "CVE-2021-42720",
    "CVE-2021-42722",
    "CVE-2021-42724",
    "CVE-2021-42728",
    "CVE-2021-42729",
    "CVE-2021-42730"
  );
  script_xref(name:"IAVA", value:"2021-A-0514-S");

  script_name(english:"Adobe Bridge 11.x < 11.1.2 Multiple Vulnerabilities (APSB21-94)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Windows host is prior to 11.1.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the apsb21-94 advisory.

  - Adobe Bridge version 11.1.1 (and earlier) is affected by a memory corruption vulnerability due to insecure
    handling of a malicious PSD file, potentially resulting in arbitrary code execution in the context of the
    current user. User interaction is required to exploit this vulnerability. (CVE-2021-42730)

  - Adobe Bridge version 11.1.1 (and earlier) is affected by a Null pointer dereference vulnerability when
    parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve
    an application denial-of-service in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2021-40750)

  - Adobe Bridge version 11.1.1 (and earlier) is affected by a double free vulnerability when parsing a
    crafted DCM file, which could result in arbitrary code execution in the context of the current user. This
    vulnerability requires user interaction to exploit. (CVE-2021-42533)

  - Adobe Bridge version 11.1.1 (and earlier) is affected by an out-of-bounds read vulnerability when parsing
    a crafted .jpe file, which could result in a read past the end of an allocated memory structure. An
    attacker could leverage this vulnerability to execute code in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2021-42719)

  - Adobe Bridge version 11.1.1 (and earlier) is affected by an out-of-bounds read vulnerability when parsing
    a crafted file, which could result in a read past the end of an allocated memory structure. An attacker
    could leverage this vulnerability to execute code in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-42720,
    CVE-2021-42722)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/120.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/415.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/476.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/788.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb21-94.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 11.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120, 125, 415, 476, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_bridge_installed.nasl");
  script_require_keys("installed_sw/Adobe Bridge", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Bridge', win_local:TRUE);

var constraints = [
  { 'min_version' : '11.0.0', 'fixed_version' : '11.1.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
