#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70587);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2013-2964");
  script_bugtraq_id(62789);

  script_name(english:"IBM Tivoli Storage Manager Client Local Buffer Overrun");
  script_summary(english:"Checks the version of IBM Tivoli Storage Manager Client.");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote Linux host is affected by
a local buffer overrun vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager Client installed on the
remote Linux host is potentially affected by a local buffer overrun
vulnerability. A local attacker could exploit this vulnerability to
gain unauthorized root access.");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21651120");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tivoli Storage Manager Client 5.5.4.1 / 6.1.5.5 / 6.2.5.0
/ 6.3.1.0 or later, or apply the workaround.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed_linux.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");
  script_require_keys("installed_sw/Tivoli Storage Manager Client", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Workaround - remove 'dsmtca' module
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Make sure the host is not Windows
if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

app = 'Tivoli Storage Manager Client';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];
package = install['Package'];
edition = install['Edition'];

fix = NULL;

if (version =~ '^6\\.3\\.' && ver_compare(ver:version, fix:'6.3.1.0', strict:FALSE) == -1) fix = '6.3.1.0';

if (edition == "Tivoli Storage Manager Backup-Archive Client")
{
  if (version =~ '^6\\.2\\.' && ver_compare(ver:version, fix:'6.2.5.0', strict:FALSE) == -1)
    fix = '6.2.5.0';
  else if (version =~ '^6\\.1\\.' && ver_compare(ver:version, fix:'6.1.5.5', strict:FALSE) == -1)
    fix = '6.1.5.5';
  else if (version =~ '^5\\.5\\.' && ver_compare(ver:version, fix:'5.5.4.1', strict:FALSE) == -1)
    fix = '5.5.4.1';
  else if (version =~ '^5\\.[0-4]\\.' || version =~ '^[0-4]\\.[0-9]+\\.')
    fix = "Please refer to the vendor for a fix.";
}

if (isnull(fix)) audit(AUDIT_PACKAGE_NOT_AFFECTED, package);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix     +
    '\n  Package           : ' + package +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
