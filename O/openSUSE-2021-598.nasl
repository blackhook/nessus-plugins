#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-598.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149548);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/15");

  script_cve_id("CVE-2019-14584");

  script_name(english:"openSUSE Security Update : shim (openSUSE-2021-598)");
  script_summary(english:"Check for the openSUSE-2021-598 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for shim fixes the following issues :

  - Updated openSUSE x86 signature

  - Avoid the error message during linux system boot
    (boo#1184454)

  - Prevent the build id being added to the binary. That can
    cause issues with the signature

Update to 15.4 (boo#1182057)

  + Rename the SBAT variable and fix the self-check of SBAT

  + sbat: add more dprint()

  + arm/aa64: Swizzle some sections to make old sbsign
    happier

  + arm/aa64 targets: put .rel* and .dyn* in .rodata

  - Change the SBAT variable name and enhance the handling
    of SBAT (boo#1182057)

Update to 15.3 for SBAT support (boo#1182057)

  + Drop gnu-efi from BuildRequires since upstream pull it
    into the

  - Generate vender-specific SBAT metadata

  + Add dos2unix to BuildRequires since Makefile requires it
    for vendor SBAT

  - Update dbx-cert.tar.xz and vendor-dbx.bin to block the
    following sign keys :

  + SLES-UEFI-SIGN-Certificate-2020-07.crt

  + openSUSE-UEFI-SIGN-Certificate-2020-07.crt

  - Check CodeSign in the signer's EKU (boo#1177315)

  - Fixed NULL pointer dereference in AuthenticodeVerify()
    (boo#1177789, CVE-2019-14584)

  - All newly released openSUSE kernels enable kernel
    lockdown and signature verification, so there is no need
    to add the prompt anymore.

  - shim-install: Support changing default shim efi binary
    in /usr/etc/default/shim and /etc/default/shim
    (boo#1177315)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184454"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected shim packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14584");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shim-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"shim-15.4-lp152.4.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"shim-debuginfo-15.4-lp152.4.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"shim-debugsource-15.4-lp152.4.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "shim / shim-debuginfo / shim-debugsource");
}
