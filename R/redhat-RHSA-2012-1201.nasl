#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1201. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61653);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-2642", "CVE-2010-3702", "CVE-2010-3704", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_bugtraq_id(43594, 43841, 43845, 45678, 46941, 47168, 47169);
  script_xref(name:"RHSA", value:"2012:1201");

  script_name(english:"RHEL 5 : tetex (RHSA-2012:1201)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tetex packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

teTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input, and creates a typesetter-independent
DeVice Independent (DVI) file as output.

teTeX embeds a copy of t1lib to rasterize bitmaps from PostScript Type
1 fonts. The following issues affect t1lib code :

Two heap-based buffer overflow flaws were found in the way t1lib
processed Adobe Font Metrics (AFM) files. If a specially crafted font
file was opened by teTeX, it could cause teTeX to crash or,
potentially, execute arbitrary code with the privileges of the user
running teTeX. (CVE-2010-2642, CVE-2011-0433)

An invalid pointer dereference flaw was found in t1lib. A specially
crafted font file could, when opened, cause teTeX to crash or,
potentially, execute arbitrary code with the privileges of the user
running teTeX. (CVE-2011-0764)

A use-after-free flaw was found in t1lib. A specially crafted font
file could, when opened, cause teTeX to crash or, potentially, execute
arbitrary code with the privileges of the user running teTeX.
(CVE-2011-1553)

An off-by-one flaw was found in t1lib. A specially crafted font file
could, when opened, cause teTeX to crash or, potentially, execute
arbitrary code with the privileges of the user running teTeX.
(CVE-2011-1554)

An out-of-bounds memory read flaw was found in t1lib. A specially
crafted font file could, when opened, cause teTeX to crash.
(CVE-2011-1552)

teTeX embeds a copy of Xpdf, an open source Portable Document Format
(PDF) file viewer, to allow adding images in PDF format to the
generated PDF documents. The following issues affect Xpdf code :

An uninitialized pointer use flaw was discovered in Xpdf. If pdflatex
was used to process a TeX document referencing a specially crafted PDF
file, it could cause pdflatex to crash or, potentially, execute
arbitrary code with the privileges of the user running pdflatex.
(CVE-2010-3702)

An array index error was found in the way Xpdf parsed PostScript Type
1 fonts embedded in PDF documents. If pdflatex was used to process a
TeX document referencing a specially crafted PDF file, it could cause
pdflatex to crash or, potentially, execute arbitrary code with the
privileges of the user running pdflatex. (CVE-2010-3704)

Red Hat would like to thank the Evince development team for reporting
CVE-2010-2642. Upstream acknowledges Jon Larimer of IBM X-Force as the
original reporter of CVE-2010-2642.

All users of tetex are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:1201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-3702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-3704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-2642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-1554"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1201";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-afm-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-afm-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-afm-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-debuginfo-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-debuginfo-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-debuginfo-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-doc-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-doc-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-doc-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-dvips-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-dvips-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-dvips-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-fonts-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-fonts-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-fonts-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-latex-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-latex-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-latex-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-xdvi-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-xdvi-3.0-33.15.el5_8.1")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-xdvi-3.0-33.15.el5_8.1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-debuginfo / tetex-doc / tetex-dvips / etc");
  }
}
