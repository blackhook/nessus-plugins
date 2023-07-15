#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94898);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_cve_id("CVE-2016-5995");
  script_bugtraq_id(93012);

  script_name(english:"IBM DB2 10.5 < Fix Pack 8 Multiple Vulnerabilities");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 10.5 running on
the remote host is prior to Fix Pack 8. It is, therefore, affected by
the following vulnerabilities :

  - A local privilege escalation vulnerability exists due to
    insecurely loading binaries planted in a location that a
    SETGID or SETUID binary would execute. A local attacker
    can exploit this, via a malicious binary, to gain root
    privileges. (CVE-2016-5995)

  - A denial of service vulnerability exists in the
    SQLNP_SCOPE_TRIAL() function due to improper handling of
    SQL statements. An authenticated, remote attacker can
    exploit this to crash the database.

  - A denial of service vulnerability exists in the Query
    Compiler QGM due to improper handling of specific
    queries. An authenticated, remote attacker can exploit
    this, via a specially crafted query, to crash the
    database.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21990061");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21633303#8");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 10.5 Fix Pack 8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5995");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_installed.nbin");
  script_require_keys("installed_sw/DB2 Server");

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
   {'min_version':'10.5', 'fixed_version':'10.5.0.8'}
];

vcf::ibm_db2::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);