#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_37110. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34316);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-0165");
  script_bugtraq_id(21964);
  script_xref(name:"HP", value:"emr_na-c01556916");
  script_xref(name:"HP", value:"HPSBUX02370");
  script_xref(name:"HP", value:"SSRT071459");

  script_name(english:"HP-UX PHNE_37110 : HP-UX Running rpcbind, Remote Denial of Service (DoS) (HPSBUX02370 SSRT071459 rev.1)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 ONC/NFS General Release/Performance Patch : 

A potential security vulnerability has been identified with HP-UX
running rpcbind. The vulnerability could be remotely exploited to
create a Denial of Service (DoS) ."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01556916
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?338fde17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_37110 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_37110 applies to a different OS release.");
}

patches = make_list("PHNE_37110", "PHNE_37568", "PHNE_39167", "PHNE_41023", "PHNE_41973", "PHNE_43577");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"NFS.KEY-CORE", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64ALIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NFS-64SLIB", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NFS-CLIENT", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NFS-CORE", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NFS-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NFS-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NFS-PRG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SERVER", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NFS-SHLIBS", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NIS-CLIENT", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NIS-CORE", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NIS-SERVER", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"NFS.NISPLUS-CORE", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-ENG-A-MAN", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
