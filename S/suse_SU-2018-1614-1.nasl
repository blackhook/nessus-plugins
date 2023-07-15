#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1614-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110445);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639");

  script_name(english:"SUSE SLES12 Security Update : libvirt (SUSE-SU-2018:1614-1) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libvirt fixes the following issues :

  - CVE-2018-3639: cpu: add support for 'ssbd' and
    'virt-ssbd' CPUID feature bits pass through
    (bsc#1092885)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3639/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181614-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d41dd69"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-1100=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-1100=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-1100=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-1100=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-libxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-libxl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-driver-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-daemon-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirt-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-xen-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-client-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-client-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-config-network-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-config-nwfilter-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-interface-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-interface-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-lxc-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-lxc-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-network-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-network-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-nodedev-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-nodedev-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-nwfilter-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-nwfilter-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-qemu-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-qemu-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-secret-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-secret-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-storage-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-storage-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-hooks-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-lxc-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-qemu-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-debugsource-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-doc-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-lock-sanlock-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-lock-sanlock-debuginfo-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-nss-2.0.0-27.42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-nss-debuginfo-2.0.0-27.42.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
