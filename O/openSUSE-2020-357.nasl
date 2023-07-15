#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-357.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(134696);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-17361", "CVE-2019-18897");

  script_name(english:"openSUSE Security Update : salt (openSUSE-2020-357)");
  script_summary(english:"Check for the openSUSE-2020-357 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for salt fixes the following issues :

  - Avoid possible user escalation upgrading salt-master
    (bsc#1157465) (CVE-2019-18897)

  - Fix unit tests failures in test_batch_async tests

  - Batch Async: Handle exceptions, properly unregister and
    close instances after running async batching to avoid
    CPU starvation of the MWorkers (bsc#1162327)

  - RHEL/CentOS 8 uses platform-python instead of python3

  - New configuration option for selection of grains in the
    minion start event.

  - Fix 'os_family' grain for Astra Linux Common Edition

  - Fix for salt-api NET API where unauthenticated attacker
    could run arbitrary code (CVE-2019-17361) (bsc#1162504)

  - Adds disabled parameter to mod_repo in aptpkg module
    Move token with atomic operation Bad API token files get
    deleted (bsc#1160931)

  - Support for Btrfs and XFS in parted and mkfs added

  - Adds list_downloaded for apt Module to enable
    pre-downloading support Adds virt.(pool|network)_get_xml
    functions

  - Various libvirt updates :

  - Add virt.pool_capabilities function

  - virt.pool_running improvements

  - Add virt.pool_deleted state

  - virt.network_define allow adding IP configuration

  - virt: adding kernel boot parameters to libvirt xml

  - Fix to scheduler when data['run'] does not exist
    (bsc#1159118)

  - Fix virt states to not fail on VMs already stopped

  - Fix applying of attributes for returner rawfile_json
    (bsc#1158940)

  - xfs: do not fail if type is not present (bsc#1153611)

  - Fix errors when running virt.get_hypervisor function

  - Align virt.full_info fixes with upstream Salt

  - Fix for log checking in x509 test

  - Read repo info without using interpolation (bsc#1135656)

  - Limiting M2Crypto to >= SLE15

  - Replacing pycrypto with M2Crypto (bsc#1165425)

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165425"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected salt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18897");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-standalone-formulas-configuration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"python2-salt-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-salt-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-api-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-bash-completion-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-cloud-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-fish-completion-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-master-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-minion-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-proxy-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-ssh-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-standalone-formulas-configuration-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-syndic-2019.2.0-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"salt-zsh-completion-2019.2.0-lp151.5.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-salt / python3-salt / salt / salt-api / etc");
}
