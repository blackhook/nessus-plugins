#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHCO_30402. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20830);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2006-0436");
  script_xref(name:"HP", value:"emr_na-c00591401");
  script_xref(name:"HP", value:"HPSBUX02091");
  script_xref(name:"HP", value:"SSRT061099");

  script_name(english:"HP-UX PHCO_30402 : HP-UX Local Increased Privilege (HPSBUX02091 SSRT061099 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 libpam_unix cumulative patch : 

A potential security vulnerability has been identified with HP-UX
systems where the vulnerability may be exploited to allow a local user
to increase privilege."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00591401
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?993f5bf8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHCO_30402 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/24");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/12");
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

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHCO_30402 applies to a different OS release.");
}

patches = make_list("PHCO_30402", "PHCO_32873", "PHCO_33215", "PHCO_34214", "PHCO_35250", "PHCO_39815", "PHCO_40837");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OS-Core.CORE-SHLIBS", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
