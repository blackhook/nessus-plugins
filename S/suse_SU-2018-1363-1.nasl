#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1363-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(110030);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715", "CVE-2018-3639");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLES12 Security Update : qemu (SUSE-SU-2018:1363-1) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu fixes several issues. This security issue was
fixed :

  - CVE-2018-3639: Spectre v4 vulnerability mitigation
    support for KVM guests (bsc#1092885). Systems with
    microprocessors utilizing speculative execution and
    speculative execution of memory reads before the
    addresses of all prior memory writes are known may allow
    unauthorized disclosure of information to an attacker
    with local user access via a side-channel analysis. This
    patch permits the new x86 cpu feature flag named 'ssbd'
    to be presented to the guest, given that the host has
    this feature, and KVM exposes it to the guest as well.
    For this feature to be enabled please use the qemu
    commandline

    -cpu $MODEL,+spec-ctrl,+ssbd so the guest OS can take
    advantage of the feature. spec-ctrl and ssbd support is
    also required in the host.

  - CVE-2017-5715: This update has the next round of Spectre
    v2 related patches, which now integrates with
    corresponding changes in libvirt. A January 2018 release
    of qemu initially addressed the Spectre v2 vulnerability
    for KVM guests by exposing the spec-ctrl feature for all
    x86 vcpu types. We remove that initial patch and now
    rely on patches from upstream (bsc#1068032). This update
    defines spec_ctrl and ibpb cpu feature flags as well as
    new cpu models which are clones of existing models with
    either -IBRS or -IBPB added to the end of the model
    name. These new vcpu models explicitly include the new
    feature(s), whereas the feature flags can be added to
    the cpu parameter as with other features. In short, for
    continued Spectre v2 protection, ensure that either the
    appropriate cpu feature flag is added to the QEMU
    command-line, or one of the new cpu models is used.
    Although migration from older versions is supported, the
    new cpu features won't be properly exposed to the guest
    until it is restarted with the cpu features explicitly
    added. A reboot is insufficient.

  - A patch is added to continue to detect Spectre v2
    mitigation features (as shown by cpuid), and if found
    provide that feature to guests, even if running on older
    KVM (kernel) versions which do not yet expose that
    feature to QEMU. (bsc#1082276)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3639/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181363-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db5bcdc1"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-950=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-950=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-x86-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-debuginfo-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-debuginfo-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-debugsource-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-debuginfo-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-kvm-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-lang-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-2.3.1-33.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-debuginfo-2.3.1-33.9.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
