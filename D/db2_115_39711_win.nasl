#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134167);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

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

  script_name(english:"IBM DB2 9.7 < FP11 39672 / 10.1 < FP6 39678 / 10.5 < FP10 39688 / 11.1.4 < FP5 39693 / 11.5 < FP0 39711 Multiple Vulnerabilities (Windows)");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/db2/Installed");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('install_func.inc');
include('misc_func.inc');
include('db2_report_func.inc');

app = 'DB2 Server';

# linux uses register_install, so we need to check this KB item
if(!get_kb_item('SMB/db2/Installed')) audit(AUDIT_NOT_INST, app);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = report_version = install['version'];

special_build = install['special_build'];
if (empty_or_null(special_build)) special_build = 'None';
if (special_build != 'None') report_version += ' with Special Build ' + special_build;

path = install['path'];

fix_ver = NULL;
fix_build = NULL;

if (version =~ '^9\\.7\\.')
{
  fix_ver = '9.7.1100.352';
  fix_build = '39672';
}
else if (version =~ '^10\\.1\\.')
{
  fix_ver = '10.1.600.580';
  fix_build = '39678';
}
else if (version =~ '^10\\.5\\.')
{
  fix_ver = '10.5.1100.2866';
}
else if (version =~ '^11\\.1\\.')
{
  fix_ver = '11.1.4050.859';
  fix_build = '39693';
}
else if (version =~ '^11\\.5\\.')
{
  fix_ver = '11.5.0.1077';
  fix_build = '39711';
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, report_version, path);

vuln = FALSE;
cmp = ver_compare(ver:version, fix:fix_ver, strict:FALSE);
# less than current fix pack
if (cmp < 0)
  vuln = TRUE;
else if (cmp == 0 && !isnull(fix_build))
{
  # missing special build or less than current special build      
  if (special_build == 'None' || ver_compare(ver:special_build, fix:fix_build, strict:FALSE) < 0)
    vuln = TRUE;
}

if (!vuln)
  audit(AUDIT_INST_PATH_NOT_VULN, app, report_version, path);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

report_db2(
    severity          : SECURITY_HOLE,
    port              : port,
    product           : app,
    path              : path,
    installed_version : version,
    fixed_version     : fix_ver,
    special_installed : special_build,
    special_fix       : fix_build);
