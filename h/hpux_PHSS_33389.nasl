#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_33389. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22462);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2005-1689");
  script_xref(name:"HP", value:"emr_na-c00768776");
  script_xref(name:"HP", value:"HPSBUX02152");
  script_xref(name:"HP", value:"SSRT5973");

  script_name(english:"HP-UX PHSS_33389 : HP-UX Kerberos Client Remote Unauthenticated Execution of Arbitrary Code (HPSBUX02152 SSRT5973 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 KRB5-Client Version 1.0 Cumulative patch : 

A potential security vulnerability has been identified with HP-UX
running Kerberos. The vulnerability may be exploited by a remote
unauthenticated user to execute arbitrary code."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00768776
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1eaa8b1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_33389 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/12");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHSS_33389 applies to a different OS release.");
}

patches = make_list("PHSS_33389", "PHSS_34991", "PHSS_39765", "PHSS_41167");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"KRB5-Client.KRB5-64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-IA32SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-IA64SLIB", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-PRG", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-RUN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"KRB5-Client.KRB5-SHLIB", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
