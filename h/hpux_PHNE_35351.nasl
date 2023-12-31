#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_35351. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26131);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2005-1192", "CVE-2007-4125", "CVE-2007-4179");
  script_xref(name:"HP", value:"emr_na-c00571568");
  script_xref(name:"HP", value:"emr_na-c01087206");
  script_xref(name:"HP", value:"emr_na-c01090656");
  script_xref(name:"HP", value:"HPSBUX01137");
  script_xref(name:"HP", value:"HPSBUX02247");
  script_xref(name:"HP", value:"HPSBUX02248");
  script_xref(name:"HP", value:"SSRT071432");
  script_xref(name:"HP", value:"SSRT071437");
  script_xref(name:"HP", value:"SSRT5954");

  script_name(english:"HP-UX PHNE_35351 : s700_800 11.11 cumulative ARPA Transport patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 cumulative ARPA Transport patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential security vulnerability has been identified
    with HP-UX running TCP/IP (IPv4). This vulnerability
    could be remotely exploited to cause a Denial of Service
    (DoS). (HPSBUX01137 SSRT5954)

  - A potential security vulnerability has been identified
    with HP-UX running ARPA Transport. The vulnerability
    could be exploited remotely to create a Denial of
    Service (DoS). (HPSBUX02248 SSRT071437)

  - A potential security vulnerability has been identified
    with HP-UX running ARPA Transport. The vulnerability
    could be exploited locally by an authorized user to
    create a Denial of Service (DoS). (HPSBUX02247
    SSRT071432)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00571568
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9aacfc53"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01090656
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f1967b3"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01087206
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25a0872a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_35351 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/24");
  script_set_attribute(attribute:"patch_modification_date", value:"2007/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
  exit(0, "The host is not affected since PHNE_35351 applies to a different OS release.");
}

patches = make_list("PHNE_35351", "PHNE_36125", "PHNE_37671", "PHNE_37898", "PHNE_38678", "PHNE_39386", "PHNE_42029");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"Networking.NET-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NET-PRG", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NET-RUN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NET-RUN-64", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NET2-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NMS2-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"Networking.NW-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.CORE2-KRN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"OS-Core.SYS-ADMIN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"ProgSupport.C-INC", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
