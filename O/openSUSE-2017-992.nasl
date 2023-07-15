#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-992.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102945);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839");

  script_name(english:"openSUSE Security Update : freerdp (openSUSE-2017-992)");
  script_summary(english:"Check for the openSUSE-2017-992 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for freerdp fixes the following issues :

  - CVE-2017-2834: Out-of-bounds write in license_recv()
    (bsc#1050714)

  - CVE-2017-2835: Out-of-bounds write in rdp_recv_tpkt_pdu
    (bsc#1050712)

  - CVE-2017-2836: Rdp Client Read Server Proprietary
    Certificate Denial of Service (bsc#1050699)

  - CVE-2017-2837: Client GCC Read Server Security Data DoS
    (bsc#1050704)

  - CVE-2017-2838: Client License Read Product Info Denial
    of Service Vulnerability (bsc#1050708)

  - CVE-2017-2839: Client License Read Challenge Packet
    Denial of Service (bsc#1050711)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050714"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freerdp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreerdp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreerdp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"freerdp-2.0.0~git.1463131968.4e66df7-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"freerdp-debuginfo-2.0.0~git.1463131968.4e66df7-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"freerdp-debugsource-2.0.0~git.1463131968.4e66df7-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"freerdp-devel-2.0.0~git.1463131968.4e66df7-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfreerdp2-2.0.0~git.1463131968.4e66df7-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfreerdp2-debuginfo-2.0.0~git.1463131968.4e66df7-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freerdp-2.0.0~git.1463131968.4e66df7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freerdp-debuginfo-2.0.0~git.1463131968.4e66df7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freerdp-debugsource-2.0.0~git.1463131968.4e66df7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freerdp-devel-2.0.0~git.1463131968.4e66df7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreerdp2-2.0.0~git.1463131968.4e66df7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreerdp2-debuginfo-2.0.0~git.1463131968.4e66df7-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp / freerdp-debuginfo / freerdp-debugsource / freerdp-devel / etc");
}
