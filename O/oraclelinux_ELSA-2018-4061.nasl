#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-4061.
#

include("compat.inc");

if (description)
{
  script_id(108939);
  script_version("1.4");
  script_cvs_date("Date: 2019/09/27 13:00:39");

  script_cve_id("CVE-2017-1002101", "CVE-2017-1002102");

  script_name(english:"Oracle Linux 7 : kubernetes (ELSA-2018-4061)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[1.9.1-2.1.5]
- Production built 1.9.1-2.1.5
- Fix the upgrade version check
- Remove w/a from [Orabug 27125915]

[1.9.1-2.1.4.dev]
- Make sure worker node upgrade properly
- [Orabug 27649898]

[1.9.1-2.1.3.dev]
- Ensure that the runtime mounts RO volumes read-only [CVE-2017-1002102]
- Update Dashboard version to v1.8.3 [CVE-2017-1002102]
- Fix nested volume mounts for read-only API data volumes [CVE-2017-1002102]
- Fixed kubeadm-setup.sh and kubeadm-registry.sh
- Add feature gate for subpath [CVE-2017-1002101]
- Add subpath e2e tests [CVE-2017-1002101]
- Lock subPath volumes [CVE-2017-1002101]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-April/007602.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kubernetes packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubeadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubectl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubelet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kubernetes");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kubeadm-1.9.1-2.1.5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kubectl-1.9.1-2.1.5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kubelet-1.9.1-2.1.5.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kubernetes-1.9.1-2.1.5.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kubeadm / kubectl / kubelet / kubernetes");
}
