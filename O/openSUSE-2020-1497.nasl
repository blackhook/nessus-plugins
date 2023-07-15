#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1497.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140727);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/05");

  script_cve_id("CVE-2020-25039", "CVE-2020-25040");

  script_name(english:"openSUSE Security Update : singularity (openSUSE-2020-1497)");
  script_summary(english:"Check for the openSUSE-2020-1497 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for singularity fixes the following issues :

New version 3.6.3, addresses the following security issues :

  - CVE-2020-25039, boo#1176705

    When a Singularity action command (run, shell, exec) is
    run with the fakeroot or user namespace option,
    Singularity will extract a container image to a
    temporary sandbox directory. Due to insecure permissions
    on the temporary directory it is possible for any user
    with access to the system to read the contents of the
    image. Additionally, if the image contains a
    world-writable file or directory, it is possible for a
    user to inject arbitrary content into the running
    container. 

  - CVE-2020-25040, boo#1176707

    When a Singularity command that results in a container
    build operation is executed, it is possible for a user
    with access to the system to read the contents of the
    image during the build. Additionally, if the image
    contains a world-writable file or directory, it is
    possible for a user to inject arbitrary content into the
    running build, which in certain circumstances may enable
    arbitrary code execution during the build and/or when
    the built container is run.

New version 3.6.2, new features / functionalities :

-Add --force option to singularity delete for non-interactive
workflows.

-Support compilation with FORTIFY_SOURCE=2 and build in pie
mode with fstack-protector enabled

  - Changed defaults / behaviours

    -Default to current architecture for singularity delete.

  - Bug Fixes

    -Respect current remote for singularity delete command.

    -Allow rw as a (noop) bind option.

    -Fix capability handling regression in overlay mount.

    -Fix LD_LIBRARY_PATH environment override regression
    with --nv/--rocm.

    -Fix environment variable duplication within singularity
    engine.

    -Use -user-xattrs for unsquashfs to avoid error with
    rootless extraction using unsquashfs 3.4

    -Correct --no-home message for 3.6 CWD behavior.

    -Don't fail if parent of cache dir not accessible.

    -Fix tests for Go 1.15 Ctty handling.

    -Fix additional issues with test images on ARM64.

    -Fix FUSE e2e tests to use container ssh_config.

    -Provide advisory message r.e. need for upper and work
    to exist in overlay images.

    -Use squashfs mem and processor limits in squashfs gzip
    check.

    -Ensure build destination path is not an empty string -
    do not overwrite CWD.

    -Don't unset PATH when interpreting legacy /environment
    files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176707"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected singularity packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:singularity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:singularity-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/22");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"singularity-3.6.3-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"singularity-debuginfo-3.6.3-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"singularity-3.6.3-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"singularity-debuginfo-3.6.3-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "singularity / singularity-debuginfo");
}
