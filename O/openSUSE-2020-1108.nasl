#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1108.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139168);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id(
    "CVE-2020-10761",
    "CVE-2020-13361",
    "CVE-2020-13362",
    "CVE-2020-13659",
    "CVE-2020-13800"
  );
  script_xref(name:"IAVB", value:"2020-B-0041-S");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2020-1108)");
  script_summary(english:"Check for the openSUSE-2020-1108 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu to version 4.2.1 fixes the following issues :

  - CVE-2020-10761: Fixed a denial of service in Network
    Block Device (nbd) support infrastructure (bsc#1172710).

  - CVE-2020-13800: Fixed a denial of service possibility in
    ati-vga emulation (bsc#1172495).

  - CVE-2020-13659: Fixed a NULL pointer dereference
    possibility in MegaRAID SAS 8708EM2 emulation
    (bsc#1172386).

  - CVE-2020-13362: Fixed an OOB access possibility in
    MegaRAID SAS 8708EM2 emulation (bsc#1172383).

  - CVE-2020-13361: Fixed an OOB access possibility in
    ES1370 audio device emulation (bsc#1172384).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172710");
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13361");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-alsa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-pa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-sdl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-gluster-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-nfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ksm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-microvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-sdl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-spice-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-spice-app-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vhost-user-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vhost-user-gpu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"qemu-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-arm-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-arm-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-audio-alsa-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-audio-alsa-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-audio-pa-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-audio-pa-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-audio-sdl-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-audio-sdl-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-curl-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-curl-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-dmg-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-dmg-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-gluster-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-gluster-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-iscsi-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-iscsi-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-nfs-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-nfs-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-rbd-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-rbd-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-ssh-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-block-ssh-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-debugsource-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-extra-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-extra-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-guest-agent-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-guest-agent-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ipxe-1.0.0+-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ksm-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-kvm-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-lang-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-linux-user-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-linux-user-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-linux-user-debugsource-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-microvm-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ppc-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ppc-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-s390-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-s390-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-seabios-1.12.1+-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-sgabios-8-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-testsuite-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-tools-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-tools-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ui-curses-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ui-curses-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ui-gtk-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ui-gtk-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ui-sdl-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ui-sdl-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ui-spice-app-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-ui-spice-app-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-vgabios-1.12.1+-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-vhost-user-gpu-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-vhost-user-gpu-debuginfo-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-x86-4.2.1-lp152.9.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"qemu-x86-debuginfo-4.2.1-lp152.9.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu / qemu-arm / qemu-arm-debuginfo / qemu-audio-alsa / etc");
}
