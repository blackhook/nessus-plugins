#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-152.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106705);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-14992", "CVE-2017-16539");

  script_name(english:"openSUSE Security Update : docker / docker-runc / containerd / etc (openSUSE-2018-152)");
  script_summary(english:"Check for the openSUSE-2018-152 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for docker, docker-runc, containerd,
golang-github-docker-libnetwork fixes several issues.

These security issues were fixed :

  - CVE-2017-16539: The DefaultLinuxSpec function in
    oci/defaults.go docker did not block /proc/scsi
    pathnames, which allowed attackers to trigger data loss
    (when certain older Linux kernels are used) by
    leveraging Docker container access to write a 'scsi
    remove-single-device' line to /proc/scsi/scsi, aka SCSI
    MICDROP (bnc#1066801)

  - CVE-2017-14992: Lack of content verification in docker
    allowed a remote attacker to cause a Denial of Service
    via a crafted image layer payload, aka gzip bombing.
    (bnc#1066210)

These non-security issues were fixed :

  - bsc#1059011: The systemd service helper script used a
    timeout of 60 seconds to start the daemon, which is
    insufficient in cases where the daemon takes longer to
    start. Instead, set the service type from 'simple' to
    'notify' and remove the now superfluous helper script.

  - bsc#1057743: New requirement with new version of
    docker-libnetwork.

  - bsc#1032287: Missing docker systemd configuration.

  - bsc#1057743: New 'symbol' for libnetwork requirement.

  - bsc#1057743: Update secrets patch to handle 'old'
    containers that have orphaned secret data no longer
    available on the host.

  - bsc#1055676: Update patches to correctly handle volumes
    and mounts when Docker is running with user namespaces
    enabled.

  - bsc#1045628:: Add patch to make the dm storage driver
    remove a container's rootfs mountpoint before attempting
    to do libdm operations on it. This helps avoid
    complications when live mounts will leak into
    containers.

  - bsc#1069758: Upgrade Docker to v17.09.1_ce (and obsolete
    docker-image-migrator).

  - bsc#1021227: bsc#1029320 bsc#1058173 -- Enable docker
    devicemapper support for deferred removal/deletion
    within Containers module.

  - bsc#1046024: Correct interaction between Docker and
    SuSEFirewall2, to avoid breaking Docker networking after
    boot.

  - bsc#1048046: Build with -buildmode=pie to make all
    binaries PIC.

  - bsc#1072798: Remove dependency on obsolete bridge-utils.

  - bsc#1064926: Set --start-timeout=2m by default to match
    upstream. 

  - bsc#1065109, bsc#1053532: Use the upstream makefile so
    that Docker can get the commit ID in `docker info`.

Please note that the 'docker-runc' package is just a rename of the old
'runc' package to match that we now ship the Docker fork of runc. This
update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072798"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected docker / docker-runc / containerd / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"containerd-0.2.9+gitr706_06b9cb351610-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-ctr-0.2.9+gitr706_06b9cb351610-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-ctr-debuginfo-0.2.9+gitr706_06b9cb351610-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-debuginfo-0.2.9+gitr706_06b9cb351610-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-debugsource-0.2.9+gitr706_06b9cb351610-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-test-0.2.9+gitr706_06b9cb351610-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-bash-completion-17.09.1_ce-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-libnetwork-0.7.0.1+gitr2066_7b2b1feb1de4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2066_7b2b1feb1de4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-1.0.0rc4+gitr3338_3f2f8b84a77f-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-debuginfo-1.0.0rc4+gitr3338_3f2f8b84a77f-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-debugsource-1.0.0rc4+gitr3338_3f2f8b84a77f-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-test-1.0.0rc4+gitr3338_3f2f8b84a77f-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-zsh-completion-17.09.1_ce-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2066_7b2b1feb1de4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"golang-github-docker-libnetwork-debugsource-0.7.0.1+gitr2066_7b2b1feb1de4-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-17.09.1_ce-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-debuginfo-17.09.1_ce-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-debugsource-17.09.1_ce-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-test-17.09.1_ce-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-test-debuginfo-17.09.1_ce-36.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-ctr / containerd-ctr-debuginfo / etc");
}
