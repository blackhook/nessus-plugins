#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3575. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130553);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-7146",
    "CVE-2019-7149",
    "CVE-2019-7150",
    "CVE-2019-7664",
    "CVE-2019-7665"
  );
  script_xref(name:"RHSA", value:"2019:3575");

  script_name(english:"RHEL 8 : elfutils (RHSA-2019:3575)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for elfutils is now available for Red Hat Enterprise Linux
8.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The elfutils packages contain a number of utility programs and
libraries related to the creation and maintenance of executable code.

The following packages have been upgraded to a later upstream version:
elfutils (0.176). (BZ#1683705)

Security Fix(es) :

* elfutils: buffer over-read in the ebl_object_note function in
eblobjnote.c in libebl (CVE-2019-7146)

* elfutils: heap-based buffer over-read in read_srclines in
dwarf_getsrclines.c in libdw (CVE-2019-7149)

* elfutils: segmentation fault in elf64_xlatetom in
libelf/elf32_xlatetom.c (CVE-2019-7150)

* elfutils: out of bound write in elf_cvt_note in libelf/note_xlate.h
(CVE-2019-7664)

* elfutils: heap-based buffer over-read in function elf32_xlatetom in
elf32_xlatetom.c (CVE-2019-7665)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 8.1 Release Notes linked from the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?774148ae");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3575");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-7146");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-7149");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-7150");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-7664");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-7665");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7665");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-7149");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-default-yama-scope");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-libelf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-libelf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-libelf-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elfutils-libs-debuginfo");
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
  rhsa = "RHSA-2019:3575";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"elfutils-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"elfutils-debugsource-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-debugsource-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-debugsource-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-debugsource-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"elfutils-default-yama-scope-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-devel-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-devel-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-devel-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"elfutils-devel-static-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-devel-static-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-devel-static-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-devel-static-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-libelf-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-libelf-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-libelf-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"elfutils-libelf-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-libelf-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-libelf-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-libelf-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-libelf-devel-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-libelf-devel-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-libelf-devel-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"elfutils-libelf-devel-static-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-libelf-devel-static-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-libelf-devel-static-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-libelf-devel-static-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-libs-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-libs-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-libs-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"elfutils-libs-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"elfutils-libs-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"elfutils-libs-debuginfo-0.176-5.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"elfutils-libs-debuginfo-0.176-5.el8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "elfutils / elfutils-debuginfo / elfutils-debugsource / etc");
  }
}
