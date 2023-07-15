#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103254);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-1434", "CVE-2017-1519");

  script_name(english:"IBM DB2 10.5 < FP8 Special Build 36828 / 11.1.2.2 < FP2 Special Build 36792 Multiple Vulnerabilities (Windows)");
  script_summary(english:"Checks the DB2 Connect signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
  remote host is either 10.5 prior to fix
  pack 8 Special Build 36828, or 11.1.2.2 prior to fix pack 2 Special
  Build 36792. It is, therefore, affected by multiple
  vulnerabilities related to denial of service and possible
  exposure of highly sensitive information as described in the advisories.

  Note: swg22005740 only affects 11.1.2.2.x.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22007183");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22005740");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate IBM DB2 Connect Special Build
based on the most recent fix pack level for your branch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1434");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2_connect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_keys("SMB/db2_connect/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("db2_report_func.inc");

app = "DB2 Connect Server";
if(!get_kb_item("SMB/db2_connect/Installed")) audit(AUDIT_NOT_INST, app);
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = report_version = install['version'];

special_build = install['special_build'];
if (empty_or_null(special_build)) special_build = "None";
if (special_build != "None") report_version += " with Special Build " + special_build;

path = install['path'];

fix_ver = NULL;
fix_build = NULL;

if (version =~ "^10\.5\.")
{
  fix_ver = "10.5.800.381";
  fix_build = "36828";
}
else if (version =~ "^11\.")
{
  fix_ver = "11.1.2020.1393";
  fix_build = "36792";
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
  if (special_build == "None" || ver_compare(ver:special_build, fix:fix_build, strict:FALSE) < 0)
    vuln = TRUE;
}

if (!vuln)
  audit(AUDIT_INST_PATH_NOT_VULN, app, report_version, path);

port = get_kb_item("SMB/transport");
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
