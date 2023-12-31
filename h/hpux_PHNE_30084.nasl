#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_30084. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16726);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"HP", value:"emr_na-c00908571");
  script_xref(name:"HP", value:"HPSBUX01002");
  script_xref(name:"HP", value:"SSRT4688");

  script_name(english:"HP-UX PHNE_30084 : HP-UX Running rpc.ypupdated, Remote Unauthorized Access (HPSBUX01002 SSRT4688 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.22 ONC/NFS General Release/Performance Patch : 

A potential security vulnerability has been found in HP-UX running
rpc.ypupdated. The vulnerability could be exploited to allow remote
unauthorized access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00908571
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e2239c7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_30084 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/29");
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

if (!hpux_check_ctx(ctx:"11.22"))
{
  exit(0, "The host is not affected since PHNE_30084 applies to a different OS release.");
}

patches = make_list("PHNE_30084");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"NFS.KEY-CORE", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64SLIB", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-ENG-A-MAN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-JPN-E-MAN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-JPN-S-MAN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-KRN", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-PRG", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SHLIBS", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-CLIENT", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-CORE", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-SERVER", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NIS-SERVER", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-CLIENT", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-CORE", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NIS2-SERVER", version:"B.11.22")) flag++;
if (hpux_check_patch(app:"NFS.NISPLUS2-CORE", version:"B.11.22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
