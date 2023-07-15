#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:4190. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131984);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/15");

  script_cve_id("CVE-2019-11729", "CVE-2019-11745");
  script_xref(name:"RHSA", value:"2019:4190");

  script_name(english:"RHEL 7 : nss, nss-softokn, nss-util (RHSA-2019:4190)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for nss, nss-softokn, and nss-util is now available for Red
Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

The nss-softokn package provides the Network Security Services
Softoken Cryptographic Module.

The nss-util packages provide utilities for use with the Network
Security Services (NSS) libraries.

Security Fix(es) :

* nss: Out-of-bounds write when passing an output buffer smaller than
the block size to NSC_EncryptUpdate (CVE-2019-11745)

* nss: Empty or malformed p256-ECDH public keys may trigger a
segmentation fault (CVE-2019-11729)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:4190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11745"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11745");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2019:4190";
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
  if (rpm_check(release:"RHEL7", reference:"nss-3.44.0-7.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-debuginfo-3.44.0-7.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-devel-3.44.0-7.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-pkcs11-devel-3.44.0-7.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-3.44.0-8.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-debuginfo-3.44.0-8.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-devel-3.44.0-8.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-3.44.0-8.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-devel-3.44.0-8.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-sysinit-3.44.0-7.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-sysinit-3.44.0-7.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-tools-3.44.0-7.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-tools-3.44.0-7.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-3.44.0-4.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-debuginfo-3.44.0-4.el7_7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-devel-3.44.0-4.el7_7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-softokn / etc");
  }
}
