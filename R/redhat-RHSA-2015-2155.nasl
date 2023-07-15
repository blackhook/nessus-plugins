#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2155. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86973);
  script_version("2.12");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9652", "CVE-2014-9653");
  script_xref(name:"RHSA", value:"2015:2155");

  script_name(english:"RHEL 7 : file (RHSA-2015:2155)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated file packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The file command is used to identify a particular file according to
the type of data the file contains. It can identify many different
file types, including Executable and Linkable Format (ELF) binary
files, system libraries, RPM packages, and different graphics formats.

Multiple denial of service flaws were found in the way file parsed
certain Composite Document Format (CDF) files. A remote attacker could
use either of these flaws to crash file, or an application using file,
via a specially crafted CDF file. (CVE-2014-0207, CVE-2014-0237,
CVE-2014-0238, CVE-2014-3479, CVE-2014-3480, CVE-2014-3487,
CVE-2014-3587)

Two flaws were found in the way file processed certain Pascal strings.
A remote attacker could cause file to crash if it was used to identify
the type of the attacker-supplied file. (CVE-2014-3478, CVE-2014-9652)

Multiple flaws were found in the file regular expression rules for
detecting various files. A remote attacker could use these flaws to
cause file to consume an excessive amount of CPU. (CVE-2014-3538)

Multiple flaws were found in the way file parsed Executable and
Linkable Format (ELF) files. A remote attacker could use these flaws
to cause file to crash, disclose portions of its memory, or consume an
excessive amount of system resources. (CVE-2014-3710, CVE-2014-8116,
CVE-2014-8117, CVE-2014-9653)

Red Hat would like to thank Thomas Jarosch of Intra2net AG for
reporting the CVE-2014-8116 and CVE-2014-8117 issues. The
CVE-2014-0207, CVE-2014-0237, CVE-2014-0238, CVE-2014-3478,
CVE-2014-3479, CVE-2014-3480, CVE-2014-3487, CVE-2014-3710 issues were
discovered by Francisco Alonso of Red Hat Product Security; the
CVE-2014-3538 issue was discovered by Jan Kaluza of the Red Hat Web
Stack Team

The file packages have been updated to ensure correct operation on
Power little endian and ARM 64-bit hardware architectures.
(BZ#1224667, BZ#1224668, BZ#1157850, BZ#1067688).

All file users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:2155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-8117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-9652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-9653"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:file-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:file-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2015:2155";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"file-5.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"file-5.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"file-debuginfo-5.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"file-devel-5.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"file-libs-5.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"file-static-5.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"python-magic-5.11-31.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-debuginfo / file-devel / file-libs / file-static / etc");
  }
}
