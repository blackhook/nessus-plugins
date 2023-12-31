#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_42988. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61591);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-3252");
  script_bugtraq_id(55076);
  script_xref(name:"HP", value:"emr_na-c03457976");

  script_name(english:"HP-UX PHSS_42988 : s700_800 11.31 Serviceguard A.11.19.00");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.31 Serviceguard A.11.19.00 : 

A potential security vulnerability has been identified in HP
Serviceguard. This vulnerability could be remotely exploited to create
a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03457976
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16631c24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_42988 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/20");
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

if (!hpux_check_ctx(ctx:"11.31"))
{
  exit(0, "The host is not affected since PHSS_42988 applies to a different OS release.");
}

patches = make_list("PHSS_42988");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"CM-Provider-MOF.CM-MOF", version:"B.06.00.00")) flag++;
if (hpux_check_patch(app:"CM-Provider-MOF.CM-PROVIDER", version:"B.06.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-Monitor.CM-CORE", version:"A.11.19.00")) flag++;
if (hpux_check_patch(app:"Cluster-Monitor.CM-CORE-COM", version:"A.11.19.00")) flag++;
if (hpux_check_patch(app:"Cluster-Monitor.CM-CORE-MAN", version:"A.11.19.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-DEN-MOF", version:"B.06.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-DEN-PROV", version:"B.06.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM", version:"B.06.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM-AUTH", version:"B.06.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM-AUTH-COM", version:"B.06.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM-COM", version:"B.06.00.00")) flag++;
if (hpux_check_patch(app:"Cluster-OM.CM-OM-TOOLS", version:"B.06.00.00")) flag++;
if (hpux_check_patch(app:"Package-CVM-CFS.CM-CVM-CFS", version:"A.11.19.00")) flag++;
if (hpux_check_patch(app:"Package-CVM-CFS.CM-CVM-CFS-COM", version:"A.11.19.00")) flag++;
if (hpux_check_patch(app:"Package-Manager.CM-PKG", version:"A.11.19.00")) flag++;
if (hpux_check_patch(app:"Package-Manager.CM-PKG-COM", version:"A.11.19.00")) flag++;
if (hpux_check_patch(app:"Package-Manager.CM-PKG-MAN", version:"A.11.19.00")) flag++;
if (hpux_check_patch(app:"SGManagerPI.SGMGRPI", version:"B.02.00")) flag++;
if (hpux_check_patch(app:"SGWBEMProviders.SGPROV-CORE", version:"A.03.00.00")) flag++;
if (hpux_check_patch(app:"SGWBEMProviders.SGPROV-MOF", version:"A.03.00.00")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
