#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_23067. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16485);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"HP", value:"emr_na-c00912118");
  script_xref(name:"HP", value:"HPSBUX00137");
  script_xref(name:"HP", value:"SSRT071336");

  script_name(english:"HP-UX PHSS_23067 : HP-UX Running Support Tools Manager, Local Denial of Service (DoS) (HPSBUX00137 SSRT071336 rev.4)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 OnlineDiag/Support Tool Manager Patch : 

HP9000 series 700/800 Support Tools Manager (xstm,cstm,stm)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00912118
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e5c598d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_23067 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/01/10");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/03/29");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHSS_23067 applies to a different OS release.");
}

patches = make_list("PHSS_23067");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Sup-Tool-Mgr.STM-CATALOGS", version:"B.11.11.00.04")) flag++;
if (hpux_check_patch(app:"Sup-Tool-Mgr.STM-SHLIBS", version:"B.11.11.00.04")) flag++;
if (hpux_check_patch(app:"Sup-Tool-Mgr.STM-UI-RUN", version:"B.11.11.00.04")) flag++;
if (hpux_check_patch(app:"Sup-Tool-Mgr.STM-UUT-RUN", version:"B.11.11.00.04")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
