#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2141-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(111503);
  script_version("1.8");
  script_cvs_date("Date: 2019/09/10 13:51:48");

  script_cve_id("CVE-2016-5008", "CVE-2017-5715", "CVE-2018-1064", "CVE-2018-3639", "CVE-2018-5748");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLES12 Security Update : libvirt (SUSE-SU-2018:2141-1) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libvirt fixes the following issues: Security issues
fixed :

  - CVE-2018-3639: Add support for 'ssbd' and 'virt-ssbd'
    CPUID feature bits to address V4 Speculative Store
    Bypass aka 'Memory Disambiguation' (bsc#1092885).

  - CVE-2018-1064: Fix denial of service problem during
    reading from guest agent (bsc#1083625).

  - CVE-2018-5748: Fix resource exhaustion via
    qemuMonitorIORead() method (bsc#1076500).

  - CVE-2016-5008: Fix that an empty VNC password disables
    authentication (bsc#987527).

  - CVE-2017-5715: Fix speculative side channel attacks aka
    'SpectreAttack' (var2) (bsc#1079869). Bug fixes :

  - bsc#980558: Fix NUMA node memory allocation.

  - bsc#968483: Restart daemons in %posttrans after
    connection drivers.

  - bsc#897352: Systemd fails to ignore LSB services.

  - bsc#956298: virsh domxml-to-native causes segfault of
    libvirtd.

  - bsc#964465: libvirtd.service causes systemd warning
    about xencommons service.

  - bsc#954872: Script block-dmmd not working as expected.

  - bsc#854343: libvirt installation run inappropriate
    systemd restart.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=854343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=897352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=954872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=956298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=964465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=968483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=980558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=987527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5008/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1064/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3639/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5748/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182141-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2121114c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-1455=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libvirt-daemon-xen-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-client-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-client-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-config-network-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-config-nwfilter-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-interface-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-interface-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-lxc-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-lxc-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-network-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-network-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-nodedev-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-nodedev-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-nwfilter-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-nwfilter-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-qemu-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-qemu-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-secret-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-secret-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-storage-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-driver-storage-debuginfo-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-lxc-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-daemon-qemu-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-debugsource-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-doc-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-lock-sanlock-1.2.5-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libvirt-lock-sanlock-debuginfo-1.2.5-27.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
