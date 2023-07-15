#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-811.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123343);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-12021");

  script_name(english:"openSUSE Security Update : singularity (openSUSE-2019-811)");
  script_summary(english:"Check for the openSUSE-2019-811 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Singularity was updated to version 2.6.0, bringing features, bugfixes
and security fixes.

Security issues fixed :

  - CVE-2018-12021: Fixed access control on systems
    supporting overlay file system (boo#1100333).

Highlights of 2.6.0 :

  - Allow admin to specify a non-standard location for
    mksquashfs binary at build time with '--with-mksquashfs'
    option #1662

  - '--nv' option will use
    [nvidia-container-cli](https://github.com/NVIDIA/libnvid
    ia-container) if installed #1681

  - [nvliblist.conf]
    (https://github.com/singularityware/singularity/blob/mas
    ter/etc/nvliblist.conf) now has a section for binaries
    #1681

  - '--nv' can be made default with all action commands in
    singularity.conf #1681

  - '--nv' can be controlled by env vars '$SINGULARITY_NV'
    and '$SINGULARITY_NV_OFF' #1681

  - Restore shim init process for proper signal handling and
    child reaping when container is initiated in its own PID
    namespace #1221

  - Add '-i' option to image.create to specify the inode
    ratio. #1759

  - Bind '/dev/nvidia*' into the container when the '--nv'
    flag is used in conjuction with the '--contain' flag
    #1358

  - Add '--no-home' option to not mount user $HOME if it is
    not the $CWD and 'mount home = yes' is set. #1761

  - Added support for OAUTH2 Docker registries like Azure
    Container Registry #1622

Highlights of 2.5.2 :

  - a new `build` command was added to replace `create` +
    `bootstrap`

  - default image format is squashfs, eliminating the need
    to specify a size

  - a `localimage` can be used as a build base, including
    ext3, sandbox, and other squashfs images

  - singularity hub can now be used as a base with the uri

  - Restore docker-extract aufs whiteout handling that
    implements correct extraction of docker container
    layers.

Bug fixes :

  - Fix 404 when using Arch Linux bootstrap #1731

  - Fix environment variables clearing while starting
    instances #1766

  - several more bug fixes, see CHANGELOG.md for details"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/NVIDIA/libnvidia-container"
  );
  # https://github.com/singularityware/singularity/blob/master/etc/nvliblist.conf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5a7b5c8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected singularity packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsingularity1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsingularity1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:singularity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:singularity-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:singularity-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:singularity-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libsingularity1-2.6.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsingularity1-debuginfo-2.6.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"singularity-2.6.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"singularity-debuginfo-2.6.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"singularity-debugsource-2.6.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"singularity-devel-2.6.0-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsingularity1 / libsingularity1-debuginfo / singularity / etc");
}
