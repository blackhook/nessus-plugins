#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151581);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/26");

  script_cve_id(
    "CVE-2021-28624",
    "CVE-2021-35989",
    "CVE-2021-35990",
    "CVE-2021-35991",
    "CVE-2021-35992"
  );

  script_name(english:"Adobe Bridge 11.x < 11.1.0 Multiple Vulnerabilities (APSB21-53)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Windows host is prior to 11.1.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the apsb21-53 advisory. Note that Nessus has not tested for this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/20.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/125.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/787.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb21-53.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 11.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 122, 125, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

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

app_info = vcf::get_app_info(app:'Adobe Bridge', win_local:TRUE);

constraints = [
  { 'min_version' : '11.0.0', 'max_version' : '11.0.2', 'fixed_version' : '11.1.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
