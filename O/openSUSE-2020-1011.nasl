#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1011.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138673);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2020-13845", "CVE-2020-13846", "CVE-2020-13847");

  script_name(english:"openSUSE Security Update : singularity (openSUSE-2020-1011)");
  script_summary(english:"Check for the openSUSE-2020-1011 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for singularity fixes the following issues :

  - New version 3.6.0. This version introduces a new
    signature format for SIF images, and changes to the
    signing / verification code to address the following
    security problems :

  - CVE-2020-13845, boo#1174150 In Singularity 3.x versions
    below 3.6.0, issues allow the ECL to be bypassed by a
    malicious user.

  - CVE-2020-13846, boo#1174148 In Singularity 3.5 the --all
    / -a option to singularity verify returns success even
    when some objects in a SIF container are not signed, or
    cannot be verified.

  - CVE-2020-13847, boo#1174152 In Singularity 3.x versions
    below 3.6.0, Singularity's sign and verify commands do
    not sign metadata found in the global header or data
    object descriptors of a SIF file, allowing an attacker
    to cause unexpected behavior. A signed container may
    verify successfully, even when it has been modified in
    ways that could be exploited to cause malicious
    behavior.

  - New features / functionalities

  - A new '--legacy-insecure' flag to verify allows
    verification of SIF signatures in the old, insecure
    format.

  - A new '-l / --logs' flag for instance list that shows
    the paths to instance STDERR / STDOUT log files.

  - The --json output of instance list now include paths to
    STDERR / STDOUT log files.

  - Singularity now supports the execution of minimal
    Docker/OCI containers that do not contain /bin/sh, e.g.
    docker://hello-world.

  - A new cache structure is used that is concurrency safe
    on a filesystem that supports atomic rename. If you
    downgrade to Singularity 3.5 or older after using 3.6
    you will need to run singularity cache clean.

  - A plugin system rework adds new hook points that will
    allow the development of plugins that modify behavior of
    the runtime. An image driver concept is introduced for
    plugins to support new ways of handling image and
    overlay mounts. Plugins built for <=3.5 are not
    compatible with 3.6.

  - The --bind flag can now bind directories from a SIF or
    ext3 image into a container.

  - The --fusemount feature to mount filesystems to a
    container via FUSE drivers is now a supported feature
    (previously an experimental hidden flag).

  - This permits users to mount e.g. sshfs and cvmfs
    filesystems to the container at runtime.

  - A new -c/--config flag allows an alternative
    singularity.conf to be specified by the root user, or
    all users in an unprivileged installation.

  - A new --env flag allows container environment variables
    to be set via the Singularity command line.

  - A new --env-file flag allows container environment
    variables to be set from a specified file.

  - A new --days flag for cache clean allows removal of
    items older than a specified number of days. Replaces
    the --name flag which is not generally useful as the
    cache entries are stored by hash, not a friendly name.

  - Changed defaults / behaviours

  - New signature format (see security fixes above).

  - Fixed spacing of singularity instance list to be
    dynamically changing based off of input lengths instead
    of fixed number of spaces to account for long instance
    names.

  - Environment variables prefixed with SINGULARITYENV_
    always take precedence over variables without
    SINGULARITYENV_ prefix.

  - The %post build section inherits environment variables
    from the base image.

  - %files from ... will now follow symlinks for sources
    that are directly specified, or directly resolved from a
    glob pattern. It will not follow symlinks found through
    directory traversal. This mirrors Docker multi-stage
    COPY behaviour.

  - Restored the CWD mount behaviour of v2, implying that
    CWD path is not recreated inside container and any
    symlinks in the CWD path are not resolved anymore to
    determine the destination path inside container.

  - The %test build section is executed the same manner as
    singularity test image.

    --fusemount with the container: default directive will
    foreground the FUSE process. Use container-daemon: for
    previous behavior.

  - Deprecate -a / --all option to sign/verify as new
    signature behavior makes this the default.

  - For more information about upstream changes, please
    check:
    https://github.com/hpcng/singularity/blob/master/CHANGEL
    OG.md

  - Removed --name flag for cache clean; replaced with
    --days."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/hpcng/singularity/blob/master/CHANGELOG.md"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected singularity packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:singularity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:singularity-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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

if ( rpm_check(release:"SUSE15.2", reference:"singularity-3.6.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"singularity-debuginfo-3.6.0-lp152.2.3.1") ) flag++;

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
