#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1049.
#

include("compat.inc");

if (description)
{
  script_id(111336);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-1064", "CVE-2018-3639", "CVE-2018-5748");
  script_xref(name:"ALAS", value:"2018-1049");

  script_name(english:"Amazon Linux 2 : libvirt (ALAS-2018-1049) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An incomplete fix for CVE-2018-5748 that affects QEMU monitor leading
to a resource exhaustion but now also triggered via QEMU guest
agent.(CVE-2018-1064)

qemu/qemu_monitor.c in libvirt allows attackers to cause a denial of
service (memory consumption) via a large QEMU reply.(CVE-2018-5748)

An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of Load & Store
instructions (a commonly used performance optimization). It relies on
the presence of a precisely-defined instruction sequence in the
privileged code as well as the fact that memory read from address to
which a recent memory write has occurred may see an older value and
subsequently cause an update into the microprocessor's data cache even
for speculatively executed instructions that never actually commit
(retire). As a result, an unprivileged attacker could use this flaw to
read privileged memory by conducting targeted cache side-channel
attacks.(CVE-2018-3639)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1049.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libvirt' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-login-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-admin-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-client-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-config-network-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-network-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-core-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-disk-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-gluster-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-iscsi-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-logical-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-mpath-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-scsi-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-kvm-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-daemon-lxc-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-debuginfo-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-devel-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-docs-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-libs-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-lock-sanlock-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-login-shell-3.9.0-14.amzn2.6")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"libvirt-nss-3.9.0-14.amzn2.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-client / libvirt-daemon / etc");
}
