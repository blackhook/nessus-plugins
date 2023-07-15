#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:4269 and 
# Oracle Linux Security Advisory ELSA-2019-4269 respectively.
#

include('compat.inc');

if (description)
{
  script_id(132667);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-9512",
    "CVE-2019-9514",
    "CVE-2019-16884",
    "CVE-2019-18466"
  );
  script_xref(name:"RHSA", value:"2019:4269");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Oracle Linux 8 : container-tools:ol8 (ELSA-2019-4269) (Ping Flood) (Reset Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2019:4269 :

An update for the container-tools:rhel8 module is now available for
Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The container-tools module contains tools for working with containers,
notably podman, buildah, skopeo, and runc.

Security Fix(es) :

* HTTP/2: flood using PING frames results in unbounded memory growth
(CVE-2019-9512)

* HTTP/2: flood using HEADERS frames results in unbounded memory
growth (CVE-2019-9514)

* runc: AppArmor/SELinux bypass with malicious image that specifies a
volume at /proc (CVE-2019-16884)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* avc: podman run --security-opt label=type:svirt_qemu_net_t
(BZ#1764318)

* backport json-file logging support to 1.4.2 (BZ#1770176)

* Selinux won't allow SCTP inter pod communication (BZ#1774382)");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-January/009494.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected container-tools:ol8 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18466");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-16884");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oci-systemd-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oci-umount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-manpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-podman-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"buildah-1.9.0-5.0.1.module+el8.1.0+5440+994fc847")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"buildah-tests-1.9.0-5.0.1.module+el8.1.0+5440+994fc847")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"cockpit-podman-4-1.module+el8.1.0+5440+994fc847")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"container-selinux-2.123.0-2.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"containernetworking-plugins-0.8.1-3.0.1.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"containers-common-0.1.37-6.0.1.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"fuse-overlayfs-0.4.1-1.module+el8.1.0+5440+994fc847")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"oci-systemd-hook-0.1.15-2.git2d0b8a3.module+el8.1.0+5440+994fc847")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"oci-umount-2.3.4-2.git87f9237.module+el8.1.0+5440+994fc847")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"podman-1.4.2-6.0.1.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"podman-docker-1.4.2-6.0.1.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"podman-manpages-1.4.2-6.0.1.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"podman-remote-1.4.2-6.0.1.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"podman-tests-1.4.2-6.0.1.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"python-podman-api-1.2.0-0.1.gitd0a45fe.module+el8.1.0+5440+994fc847")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"runc-1.0.0-61.rc8.module+el8.1.0+5460+5d763c32", rc_precedence:TRUE)) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"skopeo-0.1.37-6.0.1.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"skopeo-tests-0.1.37-6.0.1.module+el8.1.0+5460+5d763c32")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"slirp4netns-0.3.0-4.module+el8.1.0+5440+994fc847")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "buildah / buildah-tests / cockpit-podman / container-selinux / etc");
}
