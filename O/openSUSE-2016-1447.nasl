#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1447.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95753);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-7035", "CVE-2016-7797");

  script_name(english:"openSUSE Security Update : pacemaker (openSUSE-2016-1447)");
  script_summary(english:"Check for the openSUSE-2016-1447 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for pacemaker fixes the following issues :

  - remote: Allow cluster and remote LRM API versions to
    diverge (bsc#1009076)

  - libcrmcommon: fix CVE-2016-7035 (improper IPC guarding)
    (bsc#1007433)

  - sysconfig: minor tweaks (typo, wording)

  - spec: more robust check for systemd being in use

  - spec: defines instead of some globals + error
    suppression

  - various: issues discovered via valgrind and coverity

  - attrd_updater: fix usage of HAVE_ATOMIC_ATTRD

  - crmd: cl#5185 - Record pending operations in the CIB
    before they are performed (bsc#1003565)

  - ClusterMon: fix to avoid matching other process with the
    same PID

  - mcp: improve comments for sysconfig options

  - remove openssl-devel and libselinux-devel as build
    dependencies

  - tools: crm_standby --version/--help should work without
    cluster

  - libpengine: only log startup-fencing warning once

  - pacemaker.service: do not mistakenly suggest killing
    fenced

  - libcrmcommon: report errors consistently when waiting
    for data on connection (bsc#986644)

  - remote: Correctly calculate the remaining timeouts when
    receiving messages (bsc#986644)

  - libfencing: report added node ID correctly

  - crm_mon: Do not call setenv with null value

  - pengine: Do not fence a maintenance node if it shuts
    down cleanly (bsc#1000743)

  - ping: Avoid temporary files for fping check (bsc#987348)

  - all: clarify licensing and copyrights

  - crmd: Resend the shutdown request if the DC forgets

  - ping: Avoid temp files in fping_check (bsc#987348)

  - crmd: Ensure the R_SHUTDOWN is set whenever we ask the
    DC to shut us down

  - crmd: clear remote node operation history only when it
    comes up

  - libcib,libfencing,libtransition: handle memory
    allocation errors without CRM_CHECK()

  - tools: make crm_mon XML schema handle resources with
    multiple active

  - pengine: set OCF_RESKEY_CRM_meta_notify_active_* for
    multistate resources

  - pengine: avoid null dereference in new same-node
    ordering option

  - lrmd,libcluster: ensure g_hash_table_foreach() is never
    passed a null table

  - crmd: don't log warning if abort_unless_down() can't
    find down event

  - lib: Correction of the deletion of the notice
    registration.

  - stonithd: Correction of the wrong connection process
    name.

  - crmd: Keep a state of LRMD in the DC node latest.

  - pengine: avoid transition loop for start-then-stop +
    unfencing

  - libpengine: allow pe_order_same_node option for
    constraints

  - cts: Restart systemd-journald with 'systemctl restart
    systemd-journald.socket' (bsc#995365)

  - libcrmcommon: properly handle XML comments when
    comparing v2 patchset diffs

  - crmd: don't abort transitions for CIB comment changes

  - libcrmcommon: log XML comments correctly

  - libcrmcommon: remove extraneous format specifier from
    log message

  - remote: cl#5269 - Notify other clients of a new
    connection only if the handshake has completed
    (bsc#967388, bsc#1002767, CVE-2016-7797)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995365"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pacemaker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libpacemaker-devel-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpacemaker3-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpacemaker3-debuginfo-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pacemaker-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pacemaker-cli-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pacemaker-cli-debuginfo-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pacemaker-cts-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pacemaker-cts-debuginfo-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pacemaker-debuginfo-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pacemaker-debugsource-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pacemaker-remote-1.1.13-23.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pacemaker-remote-debuginfo-1.1.13-23.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpacemaker-devel / libpacemaker3 / libpacemaker3-debuginfo / etc");
}
