#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1017.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123156);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5731", "CVE-2017-5732", "CVE-2017-5733", "CVE-2017-5734", "CVE-2017-5735", "CVE-2018-3613");

  script_name(english:"openSUSE Security Update : ovmf (openSUSE-2019-1017)");
  script_summary(english:"Check for the openSUSE-2019-1017 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ovmf fixes the following issues :

Security issues fixed :

  - CVE-2018-3613: Fixed AuthVariable Timestamp zeroing
    issue on APPEND_WRITE (bsc#1115916).

  - CVE-2017-5731: Fixed privilege escalation via processing
    of malformed files in TianoCompress.c (bsc#1115917).

  - CVE-2017-5732: Fixed privilege escalation via processing
    of malformed files in BaseUefiDecompressLib.c
    (bsc#1115917).

  - CVE-2017-5733: Fixed privilege escalation via heap-based
    buffer overflow in MakeTable() function (bsc#1115917).

  - CVE-2017-5734: Fixed privilege escalation via
    stack-based buffer overflow in MakeTable() function
    (bsc#1115917).

  - CVE-2017-5735: Fixed privilege escalation via heap-based
    buffer overflow in Decode() function (bsc#1115917).

Non security issues fixed :

  - Fixed an issue with the default owner of PK/KEK/db/dbx
    and make the auto-enrollment only happen at the very
    first time. (bsc#1117998)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117998"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ovmf packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ovmf-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ovmf-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ovmf-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ovmf-x86_64-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"ovmf-2017+git1510945757.b2662641d5-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ovmf-tools-2017+git1510945757.b2662641d5-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ovmf-ia32-2017+git1510945757.b2662641d5-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ovmf-x86_64-2017+git1510945757.b2662641d5-lp150.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"qemu-ovmf-x86_64-debug-2017+git1510945757.b2662641d5-lp150.4.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ovmf / ovmf-tools / qemu-ovmf-x86_64 / qemu-ovmf-x86_64-debug / etc");
}
