#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_30173. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16493);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"HP", value:"emr_na-c00957781");
  script_xref(name:"HP", value:"HPSBUX01018");
  script_xref(name:"HP", value:"SSRT4692");

  script_name(english:"HP-UX PHSS_30173 : HP-UX XFree86, Remote Unauthorized Privileged Access, Execution of Arbitrary Code (HPSBUX01018 SSRT4692 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 Xserver cumulative patch : 

A potential security vulnerability has been identified with HP UX,
where a buffer overflow in XFree86 could be remotely exploited to gain
unauthorized privileged access."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00957781
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?010510e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_30173 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHSS_30173 applies to a different OS release.");
}

patches = make_list("PHSS_30173", "PHSS_30189", "PHSS_30501", "PHSS_30504", "PHSS_30871", "PHSS_31255", "PHSS_31281", "PHSS_31293", "PHSS_32939", "PHSS_32951", "PHSS_32955", "PHSS_32959", "PHSS_32966", "PHSS_32971", "PHSS_32976", "PHSS_32977", "PHSS_34385", "PHSS_34389", "PHSS_34390", "PHSS_34391", "PHSS_34392");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Xserver.AGRM", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-ADVANCED", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-ENTRY", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-LOAD", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-SAM", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-SLS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-UTILS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.X11-SERV", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.X11-SERV-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DBE", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DBE-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DPMS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DPMS-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-HPCR", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-HPCR-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-MBX", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-RECORD", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
