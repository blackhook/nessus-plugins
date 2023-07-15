#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72982);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Oracle RDBMS Patchset Out of Date (credentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is not up to date.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Database server installed on the remote host is
an unsupported patchset level.");
  script_set_attribute(attribute:"solution", value:
"Install the latest patchset.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_patch_info.nbin");
  script_require_keys("Oracle/Patches/local");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

get_kb_item_or_exit("Oracle/Patches/local");
installs = find_oracle_databases();
if (isnull(installs)) exit(0, 'No Oracle Databases were found on the remote host.');

res = get_oracledb_host_os_and_port();
os = res['os'];
port = res['port'];

vuln = 0;
foreach ohome(installs)
{
  version = ohome['version'];
  if (isnull(version)) continue;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] == 11 &&
    (ver[1] == 2 && ver[2] == 0 && ver[3] < 4)
  )
  {
    vuln++;
    if (max_index(split(ohome['sids'], sep:',', keep:FALSE)) > 1) s = 's ';
    else s = ' ';


    ohome_names = query_scratchpad("SELECT name FROM oracle_homes WHERE path = ?;", ohome['path']);

    ohome_name = "";

    foreach name (ohome_names)
    {
      ohome_name += name['name']+",";
    }
    ohome_name = substr(ohome_name, 0, strlen(ohome_name)-2);
    sname = "";
    foreach sid (split(ohome['sids']))
    {
      sname += get_kb_item("Oracle/"+sid+"/service_name")+",";
    }
    sname = substr(sname, 0, strlen(sname)-2);
    if(!empty_or_null(ohome['sids']))
      report += '\n  SID'+s+'             : ' + ohome['sids'];
    if(!empty_or_null(sname))
      report += '\n  Service Name'+s+'    : ' + sname;
    if(!empty_or_null(ohome_name))
      report += '\n  OHome Name'+s+'      : ' + ohome_name;
    if(!empty_or_null(ohome['path']))
      report += '\n  Oracle home path : ' + ohome['path'];
    if(!empty_or_null(version))
      report += '\n  Database version : ' + version + '\n';
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = 's of Oracle Database are';
    else s = ' of Oracle Database is';

    report =
      '\n' +
      'The following vulnerable instance'+s+' installed on the\n' +
      'remote host :\n' +
      report + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
