#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0029 and 
# CentOS Errata and Security Advisory 2018:0029 respectively.
#

include("compat.inc");

if (description)
{
  script_id(105593);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"RHSA", value:"2018:0029");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"CentOS 7 : libvirt (CESA-2018:0029) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for libvirt is now available for Red Hat Enterprise Linux 7.

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
microprocessor designs have implemented speculative execution of
instructions (a commonly used performance optimization). There are
three primary variants of the issue which differ in the way the
speculative execution can be exploited. Variant CVE-2017-5715 triggers
the speculative execution by utilizing branch target injection. It
relies on the presence of a precisely-defined instruction sequence in
the privileged code as well as the fact that memory accesses may cause
allocation into the microprocessor's data cache even for speculatively
executed instructions that never actually commit (retire). As a
result, an unprivileged attacker could use this flaw to cross the
syscall and guest/host boundaries and read privileged memory by
conducting targeted cache side-channel attacks. (CVE-2017-5715)

Note: This is the libvirt side of the CVE-2017-5715 mitigation.

Red Hat would like to thank Google Project Zero for reporting this
issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-January/022704.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4c4efc0"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5715");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/05");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-admin-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-client-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-config-network-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-network-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-kvm-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-daemon-lxc-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-devel-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-docs-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-libs-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-lock-sanlock-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-login-shell-3.2.0-14.el7_4.7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libvirt-nss-3.2.0-14.el7_4.7")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-client / libvirt-daemon / etc");
}
