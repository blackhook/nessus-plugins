#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166214);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-21618",
    "CVE-2022-21619",
    "CVE-2022-21624",
    "CVE-2022-21628",
    "CVE-2022-39399"
  );

  script_name(english:"Amazon Corretto Java 17.x < 17.0.5.8.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Amazon Corretto is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Amazon Corretto installed on the remote host is prior to 17 < 17.0.5.8.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the corretto-17-2022-Oct-18 advisory.

  - security-libs/org.ietf.jgss (CVE-2022-21618)

  - security-libs/java.security (CVE-2022-21619)

  - core-libs/javax.naming (CVE-2022-21624)

  - core-libs/java.net (CVE-2022-21628, CVE-2022-39399)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/corretto/corretto-17/blob/develop/CHANGELOG.md#corretto-version-170581
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?581d2fca");
  script_set_attribute(attribute:"solution", value:
"Update to Amazon Corretto Java 17.0.5.8.1 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21618");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:amazon:corretto");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/Java");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

if (get_kb_item('SMB/Registry/Enumerated')) audit(AUDIT_OS_NOT, 'Linux');

var app_list = ['Amazon Corretto Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '17.0', 'fixed_version' : '17.0.5.8.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
