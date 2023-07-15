#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1077-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109358);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-18030", "CVE-2017-5715", "CVE-2018-5683", "CVE-2018-7550");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLES11 Security Update : kvm (SUSE-SU-2018:1077-1) (Spectre)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kvm fixes the following issues :

  - This update has the next round of Spectre v2 related
    patches, which now integrates with corresponding changes
    in libvirt. A January 2018 release of qemu initially
    addressed the Spectre v2 vulnerability for KVM guests by
    exposing the spec-ctrl feature for all x86 vcpu types,
    which was the quick and dirty approach, but not the
    proper solution. We remove that initial patch and now
    rely on patches from upstream. This update defines
    spec_ctrl and ibpb cpu feature flags as well as new cpu
    models which are clones of existing models with either
    -IBRS or -IBPB added to the end of the model name. These
    new vcpu models explicitly include the new feature(s),
    whereas the feature flags can be added to the cpu
    parameter as with other features. In short, for
    continued Spectre v2 protection, ensure that either the
    appropriate cpu feature flag is added to the QEMU
    command-line, or one of the new cpu models is used.
    Although migration from older versions is supported, the
    new cpu features won't be properly exposed to the guest
    until it is restarted with the cpu features explicitly
    added. A reboot is insufficient.

  - A warning patch is added which attempts to detect a
    migration from a qemu version which had the quick and
    dirty fix (it only detects certain cases, but hopefully
    is helpful.) For additional information on Spectre v2 as
    it relates to QEMU, see:
    https://www.qemu.org/2018/02/14/qemu-2-11-1-and-spectre-
    update/ (CVE-2017-5715 bsc#1068032)

  - A patch is added to continue to detect Spectre v2
    mitigation features (as shown by cpuid), and if found
    provide that feature to guests, even if running on older
    KVM (kernel) versions which do not yet expose that
    feature to QEMU. (bsc#1082276) These two patches will be
    removed when we can reasonably assume everyone is
    running with the appropriate updates.

  - Security fixes for the following CVE issues:
    (bsc#1076114 CVE-2018-5683) (bsc#1083291 CVE-2018-7550)

  - This patch is already included, add here for CVE track
    (bsc#1076179 CVE-2017-18030)

  - Toolchain changes have cause the built size of
    pxe-virtio.rom to exceed 64K. Tweak rarely used strings
    in code to reduce size of the binary so it fits again.

  - Eliminate bogus use of CPUID_7_0_EDX_PRED_CMD which
    we've carried since the initial Spectre v2 patch was
    added. EDX bit 27 of CPUID Leaf 07H, Sub-leaf 0 provides
    status on STIBP, and not the PRED_CMD MSR. Exposing the
    STIBP CPUID feature bit to the guest is wrong in
    general, since the VM doesn't directly control the
    scheduling of physical hyperthreads. This is left
    strictly to the L0 hypervisor.

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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.qemu.org/2018/02/14/qemu-2-11-1-and-spectre-update/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18030/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5683/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7550/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181077-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39c75625"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-kvm-13571=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/26");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"kvm-1.4.2-60.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm");
}
