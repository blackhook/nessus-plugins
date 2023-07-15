#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134166);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/26");

  script_cve_id(
    "CVE-2019-4057",
    "CVE-2020-4135",
    "CVE-2020-4161",
    "CVE-2020-4200",
    "CVE-2020-4204",
    "CVE-2020-4230"
  );
  script_xref(name:"IAVB", value:"2020-B-0008-S");
  script_xref(name:"IAVB", value:"2020-B-0024-S");

  script_name(english:"IBM DB2 9.7 < FP11 39672 / 10.1 < FP6 39678 / 10.5 < FP10 39688 / 11.1.4 < FP5 39693 / 11.5 < FP0 39711 Multiple Vulnerabilities (UNIX)");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the remote host is either 9.7 prior to Fix Pack 11
Special Build 39672, 10.1 prior to Fix Pack 6 Special Build 39678, 10.5 prior to Fix Pack 10 Special Build 39688, or
11.1 prior to 11.1.4 Fix Pack 5 Special Build 39693, 11.5 prior to Fix Pack 0 Special Build 39711. It is, therefore,
affected by one or more of the following vulnerabilities:
  
  - An arbitrary code execution vulnerability exists due to incorrect access controls on the fenced execution 
    process. An authenticated, local attacker can exploit this, via specially crafted DB2 commands, to execute 
    arbitrary code as root. (CVE-2019-4057)
    
  - A denial of service (DoS) vulnerability exists due to incorrect handling of specially crafted packets. An
    unauthenticated, remote attacker can exploit this issue, via a specially crafted packet, to cause the
    application to stop responding. (CVE-2020-4135)

  - A denial of service (DoS) vulnerability exists due to incorrect handling of certain commands. An authenticated,
    remote attacker can exploit this issue, via specific commands, to cause the application to stop responding.
    (CVE-2020-4161)

  - A denial of service (DoS) vulnerability exists in the JDBC client due to incorrect handling of certain commands.
    An authenticated, remote attacker can exploit this issue, via specific commands, to cause the application to
    stop responding. (CVE-2020-4200)

  - Multiple buffer overflow vulnerabilities exist due to incorrect bounds checking. An authenticated,
    local attacker can exploit this to execute arbitrary code on the system with root privileges.
    (CVE-2020-4204)
    
  - A privilege escalation vulnerability exists due to incorrect handling of certain commands. An authenticated,
    local attacker can exploit this, via specially crafted DB2 commands, to gain privileged access to the system.
    (CVE-2020-4230)");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/2876307");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/2874621");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/2875251");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/2878809");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/880735");
  # https://www.ibm.com/support/pages/security-bulletin-multiple-buffer-overflow-vulnerabilities-exist-ibm%C2%AE-db2%C2%AE-leading-privilege-escalation-cve-2020-4204-0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97828fb6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'equal':'9.7.0.11', 'fixed_build':'39672'},
  {'equal':'10.1.0.6', 'fixed_build':'39678'},
  {'equal':'10.5.0.10', 'fixed_build':'39688'},
  {'equal':'11.1.4.5', 'fixed_build':'39693'},
  {'equal':'11.5.0', 'fixed_build':'39711'},
  {'min_version':'9.7', 'fixed_version':'9.7.0.11', 'fixed_display':'9.7.0.11 + Special Build 39672'},
  {'min_version':'10.1', 'fixed_version':'10.1.0.6', 'fixed_display':'10.1.0.6 + Special Build 39678'},
  {'min_version':'10.5', 'fixed_version':'10.5.0.10', 'fixed_display':'10.5.0.10 + Special Build 39688'},
  {'min_version':'11.1', 'fixed_version':'11.1.4.5', 'fixed_display':'11.1.4.5 + Special Build 39693'},
  {'min_version':'11.5', 'fixed_version':'11.5.0', 'fixed_display':'11.5.0 + Special Build 39711'}
];

vcf::ibm_db2::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);