#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_23275. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16683);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"CERT-CC", value:"2000-20");
  script_xref(name:"CERT-CC", value:"2001-02");
  script_xref(name:"HP", value:"emr_na-c00993980");
  script_xref(name:"HP", value:"HPSBUX00144");
  script_xref(name:"HP", value:"SSRT071378");

  script_name(english:"HP-UX PHNE_23275 : HP-UX running BIND, Remote Denial of Service (DoS) (HPSBUX00144 SSRT071378 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 Bind 8.1.2 Patch : 

The CERT advisories CA-2001-02 and CA-2000-20 detailed several BIND
vulnerabilities including buffer overflows, input validation error,
and disclosure environment variables and denial of service. See:
CERT/CC CA-2001-02 and CERT/CC CA-2000-20 . The Internet Software
Consortium has posted information about all vulnerabilities at the
following URL: http://www.isc.org/products/BIND/bind-security.html."
  );
  # http://www.isc.org/products/BIND/bind-security.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isc.org/downloads/BIND/bind-security.html"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00993980
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c570fd2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_23275 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  exit(0, "The host is not affected since PHNE_23275 applies to a different OS release.");
}

patches = make_list("PHNE_23275", "PHNE_28450", "PHNE_30068", "PHNE_33766", "PHNE_36185");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INET-ENG-A-MAN", version:"B.11.11")) flag++;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-RUN", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
