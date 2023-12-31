#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_25875. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16897);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"HP", value:"emr_na-c00994461");
  script_xref(name:"HP", value:"HPSBUX00194");
  script_xref(name:"HP", value:"SSRT071391");

  script_name(english:"HP-UX PHCO_25875 : HP-UX running SD, Local Unauthorized Access, Denial of Service (DoS) (HPSBUX00194 SSRT071391 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.00 Software Distributor (SD) Cumulative Patch : 

Software Distributor (SD) in incorrectly provides data views in files
not normally readable by user."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00994461
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6792a3f5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_25875 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHCO_25875 applies to a different OS release.");
}

patches = make_list("PHCO_25875", "PHCO_27672", "PHCO_28847", "PHCO_34568");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-AGENT", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-CMDS", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-ENG-A-MAN", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-FAL", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-HELP", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-HELP", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MAN", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-E-MSG", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-HELP", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MAN", version:"B.11.11.00.05.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.10.07")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.10.07.01")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.10.14")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.00.02")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.00.05")) flag++;
if (hpux_check_patch(app:"SW-DIST.SD-JPN-S-MSG", version:"B.11.11.00.05.01")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
