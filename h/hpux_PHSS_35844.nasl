#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_35844. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56069);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"HP", value:"emr_na-c00854999");

  script_name(english:"HP-UX PHSS_35844 : s700_800 11.23 OV NNM7.51 IA-64 Intermediate Patch 15");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 OV NNM7.51 IA-64 Intermediate Patch 15 : 

A potential vulnerability has been identified with HP OpenView Network
Node Manager (OV NNM). This vulnerability could be exploited remotely
to gain unauthorized access to certain facilities of the NNM server."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00854999
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6dbdfebb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_35844 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23", proc:"ia64"))
{
  exit(0, "The host is not affected since PHSS_35844 applies to a different OS release / architecture.");
}

patches = make_list("PHSS_35844", "PHSS_36386", "PHSS_36902", "PHSS_37274");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-JPN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-KOR", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-SCH", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrRtDOC.OVNNM-DOC-REUS", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVSNMP-MIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWIN", version:"B.07.50.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVWIN-MAN", version:"B.07.50.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
