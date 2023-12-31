#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91336);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/06 11:26:08");

  script_cve_id(
    "CVE-2016-0211",
    "CVE-2016-0215"
  );
  script_bugtraq_id(85979);

  script_name(english:"IBM DB2 9.7 < FP11 Special Build 35317 / 10.1 < FP5 Special Build 35316 / 10.5 < FP7 Special Build 35315 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote Windows host is either 9.7 prior to fix pack 11 special build
35317, 10.1 prior to fix pack 5 special build 35316, or 10.5 prior to
fix pack 7 special build 35315. It is, therefore, affected by the
following vulnerabilities :

  - A denial of service vulnerability exists in LUW related
    to the handling of DRDA messages. An authenticated,
    remote attacker can exploit this, via a specially
    crafted DRDA message, to cause the DB2 server to
    terminate abnormally. (CVE-2016-0211)

  - A denial of service vulnerability exists in LUW when
    handling SELECT statements with subqueries containing
    the AVG OLAP function that are applied to Oracle
    compatible databases. An authenticated, remote attacker
    can exploit this, via a specially crafted query, to
    cause the DB2 server to terminate abnormally.
    (CVE-2016-0215)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979984");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21979986");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 special build based on the most recent
fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/db2/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("db2_report_func.inc");

app = "DB2 Server";

# linux uses register_install, so we need to check this KB item
if(!get_kb_item("SMB/db2/Installed")) audit(AUDIT_NOT_INST, app);

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

product = install['product'];
if (product == "IBM Data Server Client")
  audit(AUDIT_INST_PATH_NOT_VULN, "IBM Data Server Client");

kb_version = install['version'];

ver_parts = split(kb_version, sep:".", keep:FALSE);
if (len(ver_parts) < 3)
  audit(AUDIT_VER_NOT_GRANULAR, app, kb_version);

# concatenate version parts
version = ver_parts[0]+"."+ver_parts[1]+"."+ver_parts[2];

fix_ver = NULL;
fix_build = NULL;
if (version =~ "^9\.7\.")
{
  fix_ver = "9.7.1100";
  fix_build = "35317";
}
else if (version =~ "^10\.1\.")
{
  fix_ver = "10.1.500";
  fix_build = "35316";
}
else if (version =~ "^10\.5\.")
{
  fix_ver = "10.5.700";
  fix_build = "35315";
}

path = install['path'];
special_build = install['special_build'];

if (!isnull(fix_ver))
{
  vuln = FALSE;
  cmp = ver_compare(ver:version, fix:fix_ver, strict:FALSE);
  # less than current fix pack
  if(cmp < 0)
    vuln = TRUE;
  else if (cmp == 0)
  {
    # missing special build or less than current special build
    if (special_build == "None" || ver_compare(ver:special_build, fix:fix_build, strict:FALSE) < 0)
      vuln = TRUE;
  }

}

# Report if vulnerable install was found
if (vuln)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  report_db2(
      severity          : SECURITY_WARNING,
      port              : port,
      product           : app,
      path              : path,
      installed_version : version,
      special_installed : special_build,
      fixed_version     : fix_ver,
      special_fix       : fix_build);
}
else
{
  ver_str = kb_version;
  if (special_build != "None") ver_str += " with special build " + special_build;
  audit(AUDIT_INST_VER_NOT_VULN, app, ver_str);
}
