#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:1632 and 
# Oracle Linux Security Advisory ELSA-2018-1632 respectively.
#

include("compat.inc");

if (description)
{
  script_id(109978);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639");
  script_xref(name:"RHSA", value:"2018:1632");

  script_name(english:"Oracle Linux 7 : libvirt (ELSA-2018-1632) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2018:1632 :

An update for libvirt is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libvirt library contains a C API for managing and interacting with
the virtualization capabilities of Linux and other operating systems.
In addition, libvirt provides tools for remote management of
virtualized systems.

Security Fix(es) :

* An industry-wide issue was found in the way many modern
microprocessor designs have implemented speculative execution of Load
& Store instructions (a commonly used performance optimization). It
relies on the presence of a precisely-defined instruction sequence in
the privileged code as well as the fact that memory read from address
to which a recent memory write has occurred may see an older value and
subsequently cause an update into the microprocessor's data cache even
for speculatively executed instructions that never actually commit
(retire). As a result, an unprivileged attacker could use this flaw to
read privileged memory by conducting targeted cache side-channel
attacks. (CVE-2018-3639)

Note: This is the libvirt side of the CVE-2018-3639 mitigation.

Red Hat would like to thank Ken Johnson (Microsoft Security Response
Center) and Jann Horn (Google Project Zero) for reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-May/007751.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-admin-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-client-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-config-network-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-kvm-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-daemon-lxc-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-devel-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-docs-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-libs-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-lock-sanlock-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-login-shell-3.9.0-14.el7_5.5")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libvirt-nss-3.9.0-14.el7_5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-client / libvirt-daemon / etc");
}
