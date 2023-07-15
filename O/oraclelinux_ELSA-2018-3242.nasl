#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3242 and 
# Oracle Linux Security Advisory ELSA-2018-3242 respectively.
#

include("compat.inc");

if (description)
{
  script_id(118779);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/14");

  script_cve_id("CVE-2018-10911");
  script_xref(name:"RHSA", value:"2018:3242");

  script_name(english:"Oracle Linux 7 : glusterfs (ELSA-2018-3242)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2018:3242 :

An update for glusterfs is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GlusterFS is a key building block of Red Hat Gluster Storage. It is
based on a stackable user-space design and can deliver exceptional
performance for diverse workloads. GlusterFS aggregates various
storage servers over network interconnections into one large, parallel
network file system.

The following packages have been upgraded to a later upstream version:
glusterfs (3.12.2). (BZ#1579734)

Security Fix(es) :

* glusterfs: Improper deserialization in dict.c:dict_unserialize() can
allow attackers to read arbitrary memory (CVE-2018-10911)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Michael Hanselmann (hansmi.ch) for
reporting this issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.6 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-November/008200.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected glusterfs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-gluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glusterfs-3.12.2-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glusterfs-api-3.12.2-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glusterfs-api-devel-3.12.2-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glusterfs-cli-3.12.2-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glusterfs-client-xlators-3.12.2-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glusterfs-devel-3.12.2-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glusterfs-fuse-3.12.2-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glusterfs-libs-3.12.2-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glusterfs-rdma-3.12.2-18.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python2-gluster-3.12.2-18.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs / glusterfs-api / glusterfs-api-devel / glusterfs-cli / etc");
}
