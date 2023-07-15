#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11563);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2003-0222");
  script_bugtraq_id(7453);

  script_name(english:"Oracle Net Services CREATE DATABASE LINK Query Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
  buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database, according to its version number,
  is vulnerable to a buffer overflow in the query CREATE 
  DATABASE LINK. An attacker with a database account may use 
  this flaw to gain the control on the whole database, or even 
  to obtain a shell on this host.");
  # http://web.archive.org/web/20030915014346/http://otn.oracle.com/deploy/security/pdf/2003alert54.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6719c919");
  script_set_attribute(attribute:"solution", value:
"Apply vendor-supplied patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-704");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2003-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr", 1521, 1527);

  exit(0);
}

include('global_settings.inc');

port = get_service(svc:'oracle_tnslsnr', default:1521, exit_on_fail:TRUE);
app = "Oracle TNSLSNR";

version = get_kb_item_or_exit('oracle_tnslsnr/' + port + '/version');

ver = pregmatch(pattern:"Version ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", string:version);
if (!empty_or_null(ver))
  ver = ver[1];
else
  audit(AUDIT_UNKNOWN_APP_VER, app);

fix_ver = '';
if (ver =~ "^9\.2\.") fix_ver = "9.2.0.2";
else if (ver =~ "^9\.0\.") fix_ver = "9.0.1.4";
else if (ver =~ "^8\.1\.") fix_ver = "8.1.7.4";
else if (ver =~ "^8\.0\.") fix_ver = "8.0.6.3";
else if (ver =~ "^7\.")  
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : No fixed version, please contact the vendor for support' +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}

if (ver_compare(ver:ver, fix:fix_ver, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix_ver +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, ver);
