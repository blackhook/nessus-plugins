#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74038);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/12");

  script_name(english:"McAfee VirusScan Enterprise for Linux Detection and Status");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"McAfee VirusScan Enterprise for Linux (VSEL) is installed on the
remote host. However, there is a problem with the installation; either
its services are not running or its engine and/or virus definitions
are out of date.");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score for product with out-of-date virus definitions");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_vsel_detect.nbin");
  script_require_keys("Antivirus/McAfee_VSEL/installed", "Antivirus/McAfee_VSEL/product_name");

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

kb_base = "Antivirus/McAfee_VSEL/";

get_kb_item_or_exit(kb_base+"installed");
app_name = get_kb_item_or_exit(kb_base+"product_name");

if (app_name !~ "McAfee VirusScan Enterprise for Linux") audit(AUDIT_NOT_INST, app_name);

# Get KB items.
path = get_kb_item(kb_base+"product_path");
version = get_kb_item(kb_base+"product_version");
dat_version = get_kb_item(kb_base+"dat_version");
engine_version = get_kb_item(kb_base+"engine_version");
dat_outdated = FALSE;
engine_outdated = FALSE;
port = 0;

# Placeholders if needed.
if (isnull(path)) path = "Unknown";
if (isnull(version)) version = "Unknown";

# Report if daemon is disabled.
if (get_kb_item(kb_base+"disabled"))
{

  register_install(
    app_name:app_name,
    vendor : 'McAfee',
    product : 'VirusScan Enterprise',
    path:path,
    version:version,
    cpe:"cpe:/a:mcafee:virusscan_enterprise");

  report =
    '\n' + 'The McAfeeVSEForLinux daemon is not running.' +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}

# Get data from antivirus.inc.
info = get_av_info("mcafee");
if (isnull(info)) exit(1, "Failed to get McAfee Antivirus info from antivirus.inc.");
latest_engine_version = info["last_engine_version"];
latest_dat_version = info["datvers"];

# Compare DAT version.
if (!isnull(dat_version) && ver_compare(ver:dat_version, fix:latest_dat_version, strict:FALSE) == -1)
  dat_outdated = TRUE;

# Compare engine version.
if (!isnull(engine_version) && ver_compare(ver:engine_version, fix:latest_engine_version, strict:FALSE) == -1)
  engine_outdated = TRUE;

report =
  '\n  Path           : ' + path +
  '\n  Version        : ' + version +
  '\n  DAT version    : ' + dat_version +
  '\n  Engine version : ' + engine_version +
  '\n';

if (dat_outdated) report +=
  '\nThe remote host has an out-dated version of the McAfee virus' +
  '\ndatabase. Latest version is ' + latest_dat_version +
  '\n';

if (engine_outdated) report +=
  '\nThe remote host has an out-dated version of the McAfee virus' +
  '\nengine. Latest version is ' + latest_engine_version +
  '\n';


set_kb_item (name:kb_base+"description", value:report);

# Report if required.
if (dat_outdated || engine_outdated)
{
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
{
  exit(0, "Detected McAfee VirusScan Enterprise for Linux with no known issues to report.");
}
