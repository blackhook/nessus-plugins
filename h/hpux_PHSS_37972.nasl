#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_37972. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34737);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6429", "CVE-2008-0006", "CVE-2008-1377", "CVE-2008-1379");
  script_bugtraq_id(27350, 27351, 27352, 27353, 27356, 29666, 29669);
  script_xref(name:"HP", value:"emr_na-c01543321");
  script_xref(name:"HP", value:"HPSBUX02381");
  script_xref(name:"HP", value:"SSRT080083");

  script_name(english:"HP-UX PHSS_37972 : HP-UX Running Xserver, Remote Execution of Arbitrary Code (HPSBUX02381 SSRT080083 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 Xserver cumulative patch : 

Potential security vulnerabilities have been identified with HP-UX
running Xserver. The vulnerabilities could be exploited remotely to
execute arbitrary code."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01543321
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1fab10d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_37972 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  exit(0, "The host is not affected since PHSS_37972 applies to a different OS release.");
}

patches = make_list("PHSS_37972", "PHSS_39257", "PHSS_40810", "PHSS_41260");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Xserver.AGRM", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-ADVANCED", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-ENTRY", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-LOAD", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-SAM", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-SLS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.DDX-UTILS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.OEM-SERVER", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.OEM-SERVER-PA", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.X11-SERV", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.X11-SERV-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DBE", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DBE-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DPMS", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-DPMS-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-HPCR", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-HPCR-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-MBX", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"Xserver.XEXT-RECORD", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
