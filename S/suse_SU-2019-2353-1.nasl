#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2353-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(128753);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2019:2353-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu fixes the following issues :

Security issues fixed :

CVE-2019-14378: Security fix for heap overflow in ip_reass on big
packet input (bsc#1143794).

CVE-2019-12155: Security fix for NULL pointer dereference while
releasing spice resources (bsc#1135902).

CVE-2019-13164: Security fix for qemu-bridge-helper ACL can be
bypassed when names are too long (bsc#1140402).

Bug fixes and enhancements: Add vcpu features needed for
Cascadelake-Server, Icelake-Client and Icelake-Server, especially the
foundational arch-capabilities to help with security and performance
on Intel hosts (bsc#1134880) (fate#327764).

Add support for one more security/performance related vcpu feature
(bsc#1136777) (fate#327795).

Disable file locking in the Xen PV disk backend to avoid locking
issues with PV domUs during migration. The issues triggered by the
locking can not be properly handled in libxl. The locking introduced
in qemu-2.10 was removed again in qemu-4.0 (bsc#1079730, bsc#1098403,
bsc#1111025).

Ignore csske for expanding the cpu model (bsc#1136528).

Provide qcow2 L2 caching improvements, which allows for better storage
performance in certain configurations (bsc#1139926, ECO-130).

Fixed virsh migrate-setspeed (bsc#1127077, bsc#1141043).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1134880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1139926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12155/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-13164/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14378/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192353-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0965071"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-2353=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-2353=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"qemu-block-rbd-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"qemu-x86-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"s390x", reference:"qemu-s390-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"s390x", reference:"qemu-s390-debuginfo-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-curl-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-curl-debuginfo-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-iscsi-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-iscsi-debuginfo-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-ssh-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-ssh-debuginfo-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-debugsource-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-guest-agent-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-guest-agent-debuginfo-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-kvm-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-lang-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-tools-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-tools-debuginfo-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-block-curl-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-debugsource-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-kvm-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-tools-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.11.2-5.18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-x86-2.11.2-5.18.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
