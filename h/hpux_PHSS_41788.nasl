#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_41788. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52040);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2010-4435");
  script_bugtraq_id(46261);
  script_xref(name:"HP", value:"emr_na-c02702395");
  script_xref(name:"HP", value:"HPSBUX02628");
  script_xref(name:"HP", value:"SSRT090183");
  script_xref(name:"IAVB", value:"2011-B-0026-S");

  script_name(english:"HP-UX PHSS_41788 : HP-UX Running CDE Calendar Manager, Remote Execution of Arbitrary Code (HPSBUX02628 SSRT090183 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 CDE Applications Patch : 

A potential security vulnerability has been identified with HP-UX
running CDE Calendar Manager. The vulnerability could be exploited
remotely to execute arbitrary code. References: CVE-2010-4435,
ZDI-CAN-561."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02702395
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?577429f2");
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_41788 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4435");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (!hpux_check_ctx(ctx:"11.31"))
{
  exit(0, "The host is not affected since PHSS_41788 applies to a different OS release.");
}

patches = make_list("PHSS_41788", "PHSS_42341", "PHSS_43687");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"CDE.CDE-DTTERM", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"CDE.CDE-ENG-A-MAN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"CDE.CDE-RUN", version:"B.11.31")) flag++;
if (hpux_check_patch(app:"CDE.CDE-RUN-COM", version:"B.11.31")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
