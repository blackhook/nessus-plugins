#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154724);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/23");

  script_cve_id(
    "CVE-2021-40734",
    "CVE-2021-40735",
    "CVE-2021-40736",
    "CVE-2021-40737",
    "CVE-2021-40738",
    "CVE-2021-40739",
    "CVE-2021-40740",
    "CVE-2021-40741",
    "CVE-2021-40742"
  );
  script_xref(name:"IAVA", value:"2021-A-0510-S");

  script_name(english:"Adobe Audition < 14.4.2 Multiple Vulnerabilities (APSB21-92)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Adobe Audition install on the remote Windows host is prior to
14.4.2. It is, therefore, affected by multiple vulnerabilities, including the following:

  - An arbitrary code execution vulnerability exists in Adobe Audition. An unauthenticated, local attacker
    can exploit this to bypass authentication and execute arbitrary commands. (CVE-2021-40734, CVE-2021-40735,
    CVE-2021-40736, CVE-2021-40738, CVE-2021-40739, CVE-2021-40740)

  - A NULL pointer dereference flaw exists in Adobe Audition. An unauthenticated, local attacker can exploit
    this to cause the application to stop responding. (CVE-2021-40737, CVE-2021-40742)

  - A memory access flaw exists in Adobe Audition. An unauthenticated, local attacker can exploit this to
    cause the application to stop responding. (CVE-2021-40741)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/audition/apsb21-92.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Audition version 14.4.2, 22.0, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40740");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:audition");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_audition_installed.nasl");
  script_require_keys("installed_sw/Adobe Audition", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Audition', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '14.4.2', 'fixed_display' : '14.4.2 or 22.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
