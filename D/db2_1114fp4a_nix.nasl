#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(126635);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_cve_id(
    "CVE-2019-4014",
    "CVE-2019-4101",
    "CVE-2019-4102",
    "CVE-2019-4154",
    "CVE-2019-4322",
    "CVE-2019-4386"
  );
  script_bugtraq_id(
    107686,
    109002,
    109019,
    109021,
    109024,
    109026
  );

  script_name(english:"IBM DB2 9.7 < FP11 Special Build 38744 / 10.1 < FP6 Special Build 38745 / 10.5 < FP10 Special Build 38746 / 11.1 < M4FP5 Buffer Overflow Vulnerability (UNIX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the remote host is either 9.7 prior to Fix Pack 11 
Special Build 38744, 10.1 prior to Fix Pack 6 Special Build 38745, 10.5 prior to Fix Pack 10 Special Build 38746, or 
11.1 prior to Mod 4 Fix Pack 5. It is, therefore, affected by a local privilege escalation vulnerability due to 
multiple buffer overflow vulnerabilities in DB2.");
  # https://www-01.ibm.com/support/docview.wss?uid=ibm10884444
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08deaf85");
  # https://www-01.ibm.com/support/docview.wss?uid=ibm10878793
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d40f485");
  # https://www.ibm.com/support/docview.wss?uid=ibm10880741
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dbf8ac9");
  # https://www.ibm.com/support/docview.wss?uid=ibm10880743
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88af628b");
  # https://www.ibm.com/support/docview.wss?uid=ibm10880737
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f540ba24");
  # https://www.ibm.com/support/docview.wss?uid=ibm10886809
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6f97008");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate IBM DB2 Fix Pack or Special Build based on 
  the most recent fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-4014");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_installed.nbin");
  script_require_keys("installed_sw/DB2 Server");
  script_exclude_keys("SMB/db2/Installed");

  exit(0);
}

include('vcf_extras_db2.inc');

# The remote host's OS is Windows, not Linux.
if (get_kb_item('SMB/db2/Installed'))
  audit(AUDIT_OS_NOT, 'Linux', 'Windows');

var app_info = vcf::ibm_db2::get_app_info();
# DB2 has an optional OpenSSH server that will run on
# windows.  We need to exit out if we picked up the windows
# installation that way.
if ('Windows' >< app_info['platform'])
  audit(AUDIT_HOST_NOT, 'a Linux based operating system');

var constraints = [
  {'equal':'9.7.0.11', 'fixed_build':'38744'},
  {'equal':'10.1.0.6', 'fixed_build':'38745'},
  {'equal':'10.5.0.10', 'fixed_build':'38746'},
  {'min_version':'9.7', 'fixed_version':'9.7.0.11', 'fixed_display':'9.7.0.11 + Special Build 38744'},
  {'min_version':'10.1', 'fixed_version':'10.1.0.6', 'fixed_display':'10.1.0.6 + Special Build 38745'},
  {'min_version':'10.5', 'fixed_version':'10.5.0.10', 'fixed_display':'10.5.0.10 + Special Build 38746'},
  {'min_version':'11.1', 'fixed_version':'11.1.4.5'}
];

vcf::ibm_db2::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
