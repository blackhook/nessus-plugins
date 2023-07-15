##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160842);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-28594", "CVE-2021-28633");
  script_xref(name:"IAVA", value:"2021-A-0232-S");

  script_name(english:"Adobe Creative Cloud < 2.5 Multiple Vulnerabilities (APSB21-41)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Creative Cloud instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud installed on the remote Windows host is prior to 2.5. It is, therefore, affected by
multiple vulnerabilities as referenced in the apsb21-41 advisory.

  - Adobe Creative Cloud Desktop Application (installer) version 2.4 (and earlier) is affected by an
    Uncontrolled Search Path Element vulnerability. An unauthenticated attacker could leverage this
    vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-28594)

  - Adobe Creative Cloud Desktop Application (installer) version 2.4 (and earlier) is affected by an Insecure
    temporary file creation vulnerability. An attacker could leverage this vulnerability to cause arbitrary
    file overwriting in the context of the current user. Exploitation of this issue requires physical
    interaction to the system. (CVE-2021-28633)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/379.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/427.html");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb21-41.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a33e1d3d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud version 2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28594");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(379, 427);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Creative Cloud", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Creative Cloud', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '2.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
