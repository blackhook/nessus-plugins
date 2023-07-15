#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84022);
  script_version("1.9");
  script_cvs_date("Date: 2018/07/06 11:26:08");

  script_cve_id("CVE-2014-0919");
  script_bugtraq_id(74217);

  script_name(english:"IBM DB2 9.7.x < 9.7.1000.568 Information Disclosure (credentialed check)");
  script_summary(english:"Checks the version of DB2.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM DB2 installed on the remote host is affected by an
information disclosure vulnerability due to an unspecified flaw in the
monitoring and audit features. A remote, authenticated attacker can
exploit this flaw, via a crafted series of commands, to view passwords
in SQL statements containing ENCRYPT/DECRYPT UDFs or federated DDL
statements.");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21698021");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/entdocview.wss?uid=swg1IT07547");
  script_set_attribute(attribute:"solution", value:
"Install APAR IT07547 per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2_connect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_and_db2_connect_installed.nbin");
  script_require_ports("SMB/db2/Installed", "SMB/db2_connect/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("db2_report_func.inc");

# Check each installation.
db2_installed = get_kb_item("SMB/db2/Installed");
if (db2_installed)
  db2_installs = get_kb_list("SMB/db2/*");

db2connect_installed = get_kb_item("SMB/db2_connect/Installed");
if (db2_installed)
  db2connect_installs = get_kb_list("SMB/db2_connect/*");

if (!db2_installed && !db2connect_installed)
  audit(AUDIT_NOT_INST, "DB2 and/or DB2 Connect");

info = "";
fix_version = '9.7.1000.568';
not_affected = make_list();
vuln = FALSE;

# Check DB2 first
foreach install(sort(keys(db2_installs)))
{
  if ("/Installed" >< install) continue;

  version = db2_installs[install];

  prod = install - "SMB/db2/";
  prod = prod - (strstr(prod, "/"));

  path = install - "SMB/db2/";
  path = path - (prod + "/");

  if (version =~ "^9\.7\." && ver_compare(ver:version, fix:fix_version, strict:FALSE) == -1)
    vuln = TRUE;
  else
    not_affected = make_list(not_affected, prod + ' version ' + version + ' at ' + path);
}

# Check DB2 Connect second
foreach install(sort(keys(db2connect_installs)))
{
  if ("/Installed" >< install) continue;

  version = db2connect_installs[install];

  prod = install - "SMB/db2_connect/";
  prod = prod - (strstr(prod, "/"));

  path = install - "SMB/db2_connect/";
  path = path - (prod + "/");

  if (version =~ "^9\.7\." && ver_compare(ver:version, fix:fix_version, strict:FALSE) == -1)
    vuln = TRUE;
  else
    not_affected = make_list(not_affected, prod + ' version ' + version + ' at ' + path);
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

# Report if vulnerable installs were found.
if (vuln)
{
  report_db2(port:port, path:path, product:prod, installed_version:version, fixed_version:fix_version, severity:SECURITY_WARNING);
}
else
{
  if (max_index(not_affected) > 1)
    exit(0, join(not_affected, sep:", ") + " are installed and, therefore, not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, not_affected[0]);
}
