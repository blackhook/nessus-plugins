#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_34927. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22175);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2006-0058", "CVE-2006-1173");
  script_xref(name:"CERT", value:"834865");
  script_xref(name:"HP", value:"emr_na-c00629555");
  script_xref(name:"HP", value:"emr_na-c00680632");
  script_xref(name:"HP", value:"HPSBUX02108");
  script_xref(name:"HP", value:"HPSBUX02124");
  script_xref(name:"HP", value:"SSRT061133");
  script_xref(name:"HP", value:"SSRT061159");

  script_name(english:"HP-UX PHNE_34927 : s700_800 11.04 (VVOS) sendmail(1m) 8.9.3 patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 (VVOS) sendmail(1m) 8.9.3 patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A vulnerability has been identified in sendmail which
    may allow a remote attacker to execute arbitrary code.
    References: CVE-2006-0058, US-CERT VU#834865.
    (HPSBUX02108 SSRT061133)

  - A potential security vulnerability has been identified
    with HP-UX running Sendmail processing malformed
    multipart MIME messages. This vulnerability could
    potentially allow a remote unauthenticated user to cause
    a Denial of Service (DoS). (HPSBUX02124 SSRT061159)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00629555
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f41ededc"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00680632
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a31863fc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_34927 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/22");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/22");
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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHNE_34927 applies to a different OS release.");
}

patches = make_list("PHNE_34927", "PHNE_35314");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.04")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.04")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
