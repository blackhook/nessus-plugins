#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(147891);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/02");

  script_cve_id("CVE-2020-4976");
  script_xref(name:"IAVB", value:"2021-B-0019-S");

  script_name(english:"IBM DB2 9.7 < FP11 40690 / 10.5 < FP11 40688 / 11.1 < FP6 / 11.5 < FP0 6195 File Read and Overwrite Vulnerability (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a file read and overwrite vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the remote host is either 9.7 prior to Fix Pack 11
Special Build 40690, 10.5 prior to Fix Pack 11 Special Build 40688, 11.1 prior to Fix Pack 6 , or 11.5 prior to Fix Pack 0
Special Build 6195. It is, therefore, affected by a file permissions flaw related to file handing that allows a local user to
read and write specific files.
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6427859");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Fix Pack or Special Build based on the most recent fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4976");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/db2/Installed");

  exit(0);
}

include('install_func.inc');
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
  fix_build = '40690';
}
# No linked fixes yet
#else if (version =~ '^10\\.1\\.')
#{
#  fix_ver = '10.1.600.580';
#  fix_build = '40161';
#}
else if (version =~ '^10\\.5\\.')
{
  fix_ver = '10.5.1100.2866';
  fix_build = '40688';
}
else if (version =~ '^11\\.1\\.')
{
  fix_ver = '11.1.4060.1324';
}
else if (version =~ '^11\\.5\\.')
{
  fix_ver = '11.5.5000.1587';
  fix_build = '6195';
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
    severity          : SECURITY_NOTE,
    port              : port,
    product           : app,
    path              : path,
    installed_version : version,
    fixed_version     : fix_ver,
    special_installed : special_build,
    special_fix       : fix_build);
