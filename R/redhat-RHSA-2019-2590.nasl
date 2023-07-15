#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2590. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128449);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-11772",
    "CVE-2019-11775",
    "CVE-2019-2762",
    "CVE-2019-2769",
    "CVE-2019-2786",
    "CVE-2019-2816",
    "CVE-2019-7317"
  );
  script_xref(name:"RHSA", value:"2019:2590");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 8 : java-1.8.0-ibm (RHSA-2019:2590)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for java-1.8.0-ibm is now available for Red Hat Enterprise
Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

IBM Java SE version 8 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update upgrades IBM Java SE 8 to version 8 SR5-FP40.

Security Fix(es) :

* IBM JDK: Out-of-bounds access in the String.getBytes method
(CVE-2019-11772)

* IBM JDK: Failure to privatize a value pulled out of the loop by
versioning (CVE-2019-11775)

* OpenJDK: Insufficient checks of suppressed exceptions in
deserialization (Utilities, 8212328) (CVE-2019-2762)

* OpenJDK: Unbounded memory allocation during deserialization in
Collections (Utilities, 8213432) (CVE-2019-2769)

* OpenJDK: Missing URL format validation (Networking, 8221518)
(CVE-2019-2816)

* OpenJDK: Insufficient restriction of privileges in AccessController
(Security, 8216381) (CVE-2019-2786)

* libpng: use-after-free in png_image_free in png.c (CVE-2019-7317)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:2590");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-2762");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-2769");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-2786");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-2816");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-7317");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-11772");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-11775");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-webstart");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:2590";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"java-1.8.0-ibm-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"java-1.8.0-ibm-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"java-1.8.0-ibm-demo-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"java-1.8.0-ibm-demo-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"java-1.8.0-ibm-devel-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"java-1.8.0-ibm-devel-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"java-1.8.0-ibm-headless-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"java-1.8.0-ibm-headless-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"java-1.8.0-ibm-jdbc-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"java-1.8.0-ibm-jdbc-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"java-1.8.0-ibm-plugin-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"java-1.8.0-ibm-src-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"java-1.8.0-ibm-src-1.8.0.5.40-3.el8_0")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"java-1.8.0-ibm-webstart-1.8.0.5.40-3.el8_0")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-ibm / java-1.8.0-ibm-demo / java-1.8.0-ibm-devel / etc");
  }
}
