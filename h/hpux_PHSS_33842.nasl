#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_33842. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20954);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"HP", value:"emr_na-c00604164");
  script_xref(name:"HP", value:"emr_na-c00672314");

  script_name(english:"HP-UX PHSS_33842 : s700_800 11.X OV NNM7.01 Intermediate Patch 9");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV NNM7.01 Intermediate Patch 9 : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - Potential vulnerabilities have been identified with HP
    OpenView Network Node Manager (OV NNM). These
    vulnerabilities could be exploited remotely by an
    unauthorized user to gain privileged access, execute
    arbitrary commands, or create arbitrary files.

  - Potential vulnerabilities have been identified with HP
    OpenView Network Node Manager (OV NNM). These
    vulnerabilities could be exploited remotely by an
    unauthorized user to gain privileged access. References:
    Portcullis Security Advisory 05-014."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00604164
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b3952af"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00672314
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8936e10e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_33842 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.00 11.11"))
{
  exit(0, "The host is not affected since PHSS_33842 applies to a different OS release.");
}

patches = make_list("PHSS_33842", "PHSS_35579", "PHSS_36773", "PHSS_38761", "PHSS_40705");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-CORE", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMETCore.OVNNMET-PD", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVMIB-CONTRIB", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNM-RUN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-JPN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVNNMGR-SCH", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVRPT-RUN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-JPN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgr.OVWWW-SCH", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVNNMgrMan.OVNNM-RUN-MAN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVDB-RUN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVEVENT-MIN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVMIN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWIN", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-EVNT", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatform.OVWWW-FW", version:"B.07.01.00")) flag++;
if (hpux_check_patch(app:"OVPlatformMan.OVEVENTMIN-MAN", version:"B.07.01.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
