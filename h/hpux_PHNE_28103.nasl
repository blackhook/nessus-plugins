#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_28103. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16674);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_bugtraq_id(8911);
  script_xref(name:"HP", value:"emr_na-c00958066");
  script_xref(name:"HP", value:"emr_na-c00958271");
  script_xref(name:"HP", value:"HPSBUX00215");
  script_xref(name:"HP", value:"HPSBUX00242");
  script_xref(name:"HP", value:"HPSBUX0401");
  script_xref(name:"HP", value:"SSRT2330");
  script_xref(name:"HP", value:"SSRT2336");
  script_xref(name:"HP", value:"SSRT2339");

  script_name(english:"HP-UX PHNE_28103 : s700_800 11.11 ONC/NFS General Release/Performance Patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 ONC/NFS General Release/Performance Patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential vulnerability in ypxfrd may allow a local
    user to read files without permission.

  - Potential buffer overflow in XDR library. (HPSBUX00215
    SSRT2336)

  - Potential security vulnerability in rpc.yppasswdd.
    (HPSBUX00242 SSRT2330)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00958066
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69026abe"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00958271
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a018042e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_28103 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/05");
  script_set_attribute(attribute:"patch_modification_date", value:"2004/01/07");
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
  exit(0, "The host is not affected since PHNE_28103 applies to a different OS release.");
}

patches = make_list("PHNE_28103", "PHNE_28568", "PHNE_28983", "PHNE_29211", "PHNE_29303", "PHNE_29783", "PHNE_29883", "PHNE_30378", "PHNE_30380", "PHNE_30661", "PHNE_31097", "PHNE_31929", "PHNE_32477", "PHNE_32811", "PHNE_33315", "PHNE_33498", "PHNE_33971", "PHNE_34293", "PHNE_34662", "PHNE_34938", "PHNE_35418", "PHNE_35871", "PHNE_36168", "PHNE_37110", "PHNE_37568", "PHNE_39167", "PHNE_41023", "PHNE_41973", "PHNE_43577");
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


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
