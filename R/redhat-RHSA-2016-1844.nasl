#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1844. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93450);
  script_version("2.14");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8934", "CVE-2016-1541", "CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809", "CVE-2016-5418", "CVE-2016-5844", "CVE-2016-6250", "CVE-2016-7166");
  script_xref(name:"RHSA", value:"2016:1844");

  script_name(english:"RHEL 7 : libarchive (RHSA-2016:1844)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libarchive is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libarchive programming library can create and read several
different streaming archive formats, including GNU tar, cpio, and ISO
9660 CD-ROM images. Libarchive is used notably in the bsdtar utility,
scripting language bindings such as python-libarchive, and several
popular desktop file managers.

Security Fix(es) :

* A flaw was found in the way libarchive handled hardlink archive
entries of non-zero size. Combined with flaws in libarchive's file
system sandboxing, this issue could cause an application using
libarchive to overwrite arbitrary files with arbitrary data from the
archive. (CVE-2016-5418)

* Multiple out-of-bounds write flaws were found in libarchive.
Specially crafted ZIP, 7ZIP, or RAR files could cause a heap overflow,
potentially allowing code execution in the context of the application
using libarchive. (CVE-2016-1541, CVE-2016-4300, CVE-2016-4302)

* Multiple out-of-bounds read flaws were found in libarchive.
Specially crafted LZA/LZH, AR, MTREE, ZIP, TAR, or RAR files could
cause the application to read data out of bounds, potentially
disclosing a small amount of application memory, or causing an
application crash. (CVE-2015-8919, CVE-2015-8920, CVE-2015-8921,
CVE-2015-8923, CVE-2015-8924, CVE-2015-8925, CVE-2015-8926,
CVE-2015-8928, CVE-2015-8934)

* Multiple NULL pointer dereference flaws were found in libarchive.
Specially crafted RAR, CAB, or 7ZIP files could cause an application
using libarchive to crash. (CVE-2015-8916, CVE-2015-8917,
CVE-2015-8922)

* Multiple infinite loop / resource exhaustion flaws were found in
libarchive. Specially crafted GZIP or ISO files could cause the
application to consume an excessive amount of resources, eventually
leading to a crash on memory exhaustion. (CVE-2016-7166,
CVE-2015-8930)

* A denial of service vulnerability was found in libarchive. A
specially crafted CPIO archive containing a symbolic link to a large
target path could cause memory allocation to fail, causing an
application using libarchive that attempted to view or extract such
archive to crash. (CVE-2016-4809)

* An integer overflow flaw, leading to a buffer overflow, was found in
libarchive's construction of ISO9660 volumes. Attempting to create an
ISO9660 volume with 2 GB or 4 GB file names could cause the
application to attempt to allocate 20 GB of memory. If this were to
succeed, it could lead to an out of bounds write on the heap and
potential code execution. (CVE-2016-6250)

* Multiple instances of undefined behavior due to arithmetic overflow
were found in libarchive. Specially crafted MTREE archives, Compress
streams, or ISO9660 volumes could potentially cause the application to
fail to read the archive, or to crash. (CVE-2015-8931, CVE-2015-8932,
CVE-2016-5844)

Red Hat would like to thank Insomnia Security for reporting
CVE-2016-5418."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-1541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7166"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsdcpio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsdtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libarchive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libarchive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libarchive-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1844";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"bsdcpio-3.1.2-10.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"bsdcpio-3.1.2-10.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"bsdtar-3.1.2-10.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"bsdtar-3.1.2-10.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libarchive-3.1.2-10.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libarchive-debuginfo-3.1.2-10.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libarchive-devel-3.1.2-10.el7_2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsdcpio / bsdtar / libarchive / libarchive-debuginfo / etc");
  }
}
