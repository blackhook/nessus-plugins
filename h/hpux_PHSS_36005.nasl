#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_36005. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26887);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-6195");
  script_xref(name:"HP", value:"emr_na-c01294212");
  script_xref(name:"HP", value:"HPSBUX02294");
  script_xref(name:"HP", value:"SSRT071451");
  script_xref(name:"TRA", value:"TRA-2007-12");

  script_name(english:"HP-UX PHSS_36005 : HP-UX Running DCE, Remote Denial of Service (DoS) (HPSBUX02294 SSRT071451 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 HP DCE 1.9 client cumulative patch : 

A potential security vulnerability has been identified with HP-UX
applications running DCE such as Software Distributor (SD). The
vulnerability could be exploited remotely to create a denial of
service (DoS)."
  );
  # http://www.zerodayinitiative.com/advisories/ZDI-07-079
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.zerodayinitiative.com/advisories/ZDI-07-079"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01294212
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d99764ad"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2007-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_36005 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHSS_36005 applies to a different OS release.");
}

patches = make_list("PHSS_36005", "PHSS_38258", "PHSS_42853");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DCE-Core.DCE-COR-64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-COR-IA-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-COR-PA-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-CORE-DTS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-CORE-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-CORE-SHLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCE-IA64-SHLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-Core.DCEC-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-CoreTools.DCE-BPRG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"DCE-CoreTools.DCEP-ENG-A-MAN", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
