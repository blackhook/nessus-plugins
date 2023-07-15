#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-185.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106917);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11332", "CVE-2017-11358", "CVE-2017-11359", "CVE-2017-15370", "CVE-2017-15371", "CVE-2017-15372", "CVE-2017-15642", "CVE-2017-18189");

  script_name(english:"openSUSE Security Update : sox (openSUSE-2018-185)");
  script_summary(english:"Check for the openSUSE-2018-185 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for sox fixes the following issues :

  - CVE-2017-11332: Fixed the startread function in wav.c,
    which allowed remote attackers to cause a DoS
    (divide-by-zero) via a crafted wav file. (boo#1081140)

  - CVE-2017-11358: Fixed the read_samples function in
    hcom.c, which allowed remote attackers to cause a DoS
    (invalid memory read) via a crafted hcom file.
    (boo#1081141)

  - CVE-2017-11359: Fixed the wavwritehdr function in wav.c,
    which allowed remote attackers to cause a DoS
    (divide-by-zero) when converting a a crafted snd file to
    a wav file. (boo#1081142)

  - CVE-2017-15370: Fixed a heap-based buffer overflow in
    the ImaExpandS function of ima_rw.c, which allowed
    remote attackers to cause a DoS during conversion of a
    crafted audio file. (boo#1063439)

  - CVE-2017-15371: Fixed an assertion abort in the function
    sox_append_comment() in formats.c, which allowed remote
    attackers to cause a DoS during conversion of a crafted
    audio file. (boo#1063450)

  - CVE-2017-15372: Fixed a stack-based buffer overflow in
    the lsx_ms_adpcm_block_expand_i function of adpcm.c,
    which allowed remote attackers to cause a DoS during
    conversion of a crafted audio file. (boo#1063456)

  - CVE-2017-15642: Fixed an Use-After-Free vulnerability in
    lsx_aiffstartread in aiff.c, which could be triggered by
    an attacker by providing a malformed AIFF file.
    (boo#1064576)

  - CVE-2017-18189: Fixed a NULL pointer dereference
    triggered by a corrupt header specifying zero channels
    in the startread function in xa.c, which allowed remote
    attackers to cause a DoS (boo#1081146)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081146"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsox3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsox3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"libsox3-14.4.2-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsox3-debuginfo-14.4.2-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sox-14.4.2-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sox-debuginfo-14.4.2-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sox-debugsource-14.4.2-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sox-devel-14.4.2-5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsox3 / libsox3-debuginfo / sox / sox-debuginfo / sox-debugsource / etc");
}
