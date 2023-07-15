#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112114);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-1156",
    "CVE-2018-1157",
    "CVE-2018-1158",
    "CVE-2018-1159"
  );

  script_name(english:"MikroTik RouterOS <  6.40.9 / 6.42.7 / 6.43 multiple vulnerabilities.");

  script_set_attribute(attribute:"synopsis", value:
"The remote networking device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote networking device
is running a version of MikroTik prior to 6.40.9, 6.41.x <
6.42.7, or 6.43. It, therefore, vulnerable to multiple vulnerabilities.");
  # https://blog.mikrotik.com/security/security-issues-discovered-by-tenable.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?237622b9");
  # https://forum.mikrotik.com/viewtopic.php?f=21&t=138331
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9e2af40");
  # https://forum.mikrotik.com/viewtopic.php?f=21&t=138228
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c37b423c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MikroTik RouterOS 6.40.9 / 6.42.7 / 6.43 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1156");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mikrotik_detect.nasl");
  script_require_keys("MikroTik/RouterOS/Version");

  exit(0);
}

include("vcf.inc");
include("audit.inc");

app = "MikroTik";
kb_ver = "MikroTik/RouterOS/Version";
# The version can be NULL when only SSH service is running.
version = get_kb_item_or_exit(kb_ver);
if(empty_or_null(version)) audit(AUDIT_UNKNOWN_APP_VER, app);

app_info = vcf::get_app_info(app:app, kb_ver:kb_ver, service:FALSE);

constraints = [{ "fixed_version" : "6.40.9" },
               { "min_version" : "6.41", "fixed_version" : "6.42.7" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
