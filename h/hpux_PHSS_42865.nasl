#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_42865. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58612);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-0131");
  script_bugtraq_id(52860);
  script_xref(name:"HP", value:"emr_na-c03261413");
  script_xref(name:"HP", value:"HPSBUX02758");
  script_xref(name:"HP", value:"SSRT100774");

  script_name(english:"HP-UX PHSS_42865 : HP-UX running DCE, Remote Denial of Service (DoS) (HPSBUX02758 SSRT100774 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 HP DCE/9000 1.8 Server/DevTools cum. patch : 

A potential security vulnerability has been identified in HP-UX
running DCE. The vulnerability could be exploited remotely to create a
Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03261413
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1118fbbb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_42865 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/06");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHSS_42865 applies to a different OS release.");
}

patches = make_list("PHSS_42865");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"DCE-C-Tools.DCE-TOOLS-LIB", version:"B.11.11.10")) flag++;
if (hpux_check_patch(app:"DCE-CDS-Server.CDS-SERVER", version:"B.11.11.10")) flag++;
if (hpux_check_patch(app:"DCE-CoreAdmin.DCE-CDSBROWSER", version:"B.11.11.10")) flag++;
if (hpux_check_patch(app:"DCE-CoreTools.DCE-BPRG", version:"B.11.11.10")) flag++;
if (hpux_check_patch(app:"DCE-CoreTools.DCEP-ENG-A-MAN", version:"B.11.11.10")) flag++;
if (hpux_check_patch(app:"DCE-SEC-Server.SEC-SERVER", version:"B.11.11.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
