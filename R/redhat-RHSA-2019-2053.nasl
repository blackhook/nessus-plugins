#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2053. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127662);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:47");

  script_cve_id("CVE-2016-3186", "CVE-2018-10779", "CVE-2018-10963", "CVE-2018-12900", "CVE-2018-17100", "CVE-2018-17101", "CVE-2018-18557", "CVE-2018-18661", "CVE-2018-7456", "CVE-2018-8905");
  script_xref(name:"RHSA", value:"2019:2053");

  script_name(english:"RHEL 7 : libtiff (RHSA-2019:2053)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libtiff is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

Security Fix(es) :

* libtiff: buffer overflow in gif2tiff (CVE-2016-3186)

* libtiff: Heap-based buffer overflow in the cpSeparateBufToContigBuf
function resulting in a denial of service or possibly code execution
(CVE-2018-12900)

* libtiff: Out-of-bounds write in tif_jbig.c (CVE-2018-18557)

* libtiff: NULL pointer dereference in
tif_print.c:TIFFPrintDirectory() causes a denial of service
(CVE-2018-7456)

* libtiff: heap-based buffer overflow in tif_lzw.c:LZWDecodeCompat()
allows for denial of service (CVE-2018-8905)

* libtiff: heap-based buffer over-read in TIFFWriteScanline function
in tif_write.c (CVE-2018-10779)

* libtiff: reachable assertion in TIFFWriteDirectorySec function in
tif_dirwrite.c (CVE-2018-10963)

* libtiff: Integer overflow in multiply_ms in tools/ppm2tiff.c
(CVE-2018-17100)

* libtiff: Two out-of-bounds writes in cpTags in tools/tiff2bw.c and
tools/ pal2rgb.c (CVE-2018-17101)

* libtiff: tiff2bw tool failed memory allocation leads to crash
(CVE-2018-18661)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-7456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-8905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-10963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-12900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-17100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-17101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-18557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-18661"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2019:2053";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL7", reference:"libtiff-4.0.3-32.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libtiff-debuginfo-4.0.3-32.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libtiff-devel-4.0.3-32.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libtiff-static-4.0.3-32.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libtiff-tools-4.0.3-32.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libtiff-tools-4.0.3-32.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-debuginfo / libtiff-devel / libtiff-static / etc");
  }
}
