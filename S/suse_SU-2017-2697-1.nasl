#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2697-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103772);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libvirt (SUSE-SU-2017:2697-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libvirt fixes several issues. This security issue was
fixed :

  - bsc#1053600: Escape ssh commed line to prevent
    interpreting malicious hostname as arguments, allowing
    for command execution

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1052151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1053600"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172697-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92c490d1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-1668=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-1668=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1668=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1668=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1668=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-xen-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-client-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-client-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-config-network-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-config-nwfilter-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-interface-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-interface-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-lxc-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-lxc-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-network-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-network-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-nodedev-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-nodedev-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-nwfilter-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-nwfilter-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-qemu-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-qemu-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-secret-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-secret-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-storage-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-driver-storage-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-lxc-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-daemon-qemu-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-debugsource-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-doc-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-lock-sanlock-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-lock-sanlock-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-nss-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libvirt-nss-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-client-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-client-32bit-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-client-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-client-debuginfo-32bit-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-config-network-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-config-nwfilter-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-interface-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-lxc-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-network-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-network-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-nodedev-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-nwfilter-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-qemu-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-secret-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-debuginfo-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-lxc-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-qemu-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-daemon-xen-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-debugsource-2.0.0-27.20.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirt-doc-2.0.0-27.20.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
