#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108521);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/08");

  script_cve_id("CVE-2018-7445");
  script_bugtraq_id(103427);
  script_xref(name:"EDB-ID", value:"44290");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");

  script_name(english:"MikroTik RouterOS < 6.40.7 or 6.41.x < 6.41.3 SMB Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote networking device is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote networking device
is running a version of MikroTik RouterOS prior to 6.40.7 or 6.41.x
prior to 6.41.3. It is, therefore, affected by a remote SMB buffer
overflow vulnerability that can be leveraged by an unauthenticated,
remote attacker to execute arbitrary code.");
  # https://www.coresecurity.com/advisories/mikrotik-routeros-smb-buffer-overflow
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e50beb7");
  # https://www.tenable.com/blog/slingshot-malware-uses-iot-device-in-targeted-attacks
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f90999e3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MikroTik RouterOS 6.40.7, 6.41.3 and later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7445");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mikrotik:routeros");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mikrotik_detect.nasl", "ssh_detect.nasl");
  script_require_keys("MikroTik/RouterOS/Version");

  exit(0);
}

include("vcf.inc");
include("audit.inc");

app = "MikroTik";
kb_ver = "MikroTik/RouterOS/Version";

version = get_kb_item_or_exit(kb_ver);
if(empty_or_null(version)) audit(AUDIT_UNKNOWN_APP_VER, app);

app_info = vcf::get_app_info(app:app, kb_ver:kb_ver, service:FALSE);

constraints = [{ "fixed_version" : "6.40.7" },
               { "min_version" : "6.41", "fixed_version" : "6.41.3" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
