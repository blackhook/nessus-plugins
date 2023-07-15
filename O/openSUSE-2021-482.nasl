#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-482.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148210);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2020-14928", "CVE-2020-16117");

  script_name(english:"openSUSE Security Update : evolution-data-server (openSUSE-2021-482)");
  script_summary(english:"Check for the openSUSE-2021-482 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for evolution-data-server fixes the following issues :

  - CVE-2020-16117: Fix crash on malformed server response
    with minimal capabilities (bsc#1174712).

  - CVE-2020-14928: Response injection via STARTTLS in SMTP
    and POP3 (bsc#1173910).

  - Fix buffer overrun when parsing base64 data
    (bsc#1182882).

This update for evolution-ews fixes the following issue :

  - Fix buffer overrun when parsing base64 data
    (bsc#1182882).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182882"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected evolution-data-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-data-server-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-ews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-ews-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-ews-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evolution-ews-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcamel-1_2-62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcamel-1_2-62-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcamel-1_2-62-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcamel-1_2-62-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebackend-1_2-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebackend-1_2-10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebackend-1_2-10-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebackend-1_2-10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebook-1_2-20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebook-1_2-20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebook-1_2-20-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebook-1_2-20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebook-contacts-1_2-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebook-contacts-1_2-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebook-contacts-1_2-3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libebook-contacts-1_2-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecal-2_0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecal-2_0-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecal-2_0-1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libecal-2_0-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedata-book-1_2-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedata-book-1_2-26-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedata-book-1_2-26-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedata-book-1_2-26-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedata-cal-2_0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedata-cal-2_0-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedata-cal-2_0-1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedata-cal-2_0-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedataserver-1_2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedataserver-1_2-24-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedataserver-1_2-24-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedataserver-1_2-24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedataserverui-1_2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedataserverui-1_2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedataserverui-1_2-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libedataserverui-1_2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Camel-1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EBackend-1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EBook-1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EBookContacts-1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-ECal-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EDataBook-1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EDataCal-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EDataServer-1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EDataServerUI-1_2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/29");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"evolution-data-server-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"evolution-data-server-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"evolution-data-server-debugsource-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"evolution-data-server-devel-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"evolution-data-server-lang-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"evolution-ews-lang-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcamel-1_2-62-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcamel-1_2-62-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libebackend-1_2-10-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libebackend-1_2-10-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libebook-1_2-20-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libebook-1_2-20-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libebook-contacts-1_2-3-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libebook-contacts-1_2-3-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libecal-2_0-1-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libecal-2_0-1-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libedata-book-1_2-26-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libedata-book-1_2-26-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libedata-cal-2_0-1-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libedata-cal-2_0-1-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libedataserver-1_2-24-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libedataserver-1_2-24-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libedataserverui-1_2-2-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libedataserverui-1_2-2-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-Camel-1_2-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-EBackend-1_2-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-EBook-1_2-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-EBookContacts-1_2-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-ECal-2_0-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-EDataBook-1_2-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-EDataCal-2_0-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-EDataServer-1_2-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-EDataServerUI-1_2-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"evolution-data-server-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"evolution-data-server-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"evolution-ews-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"evolution-ews-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"evolution-ews-debugsource-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libcamel-1_2-62-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libcamel-1_2-62-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libebackend-1_2-10-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libebackend-1_2-10-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libebook-1_2-20-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libebook-1_2-20-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libebook-contacts-1_2-3-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libebook-contacts-1_2-3-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libecal-2_0-1-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libecal-2_0-1-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libedata-book-1_2-26-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libedata-book-1_2-26-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libedata-cal-2_0-1-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libedata-cal-2_0-1-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libedataserver-1_2-24-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libedataserver-1_2-24-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libedataserverui-1_2-2-32bit-3.34.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libedataserverui-1_2-2-32bit-debuginfo-3.34.4-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution-data-server / evolution-data-server-debuginfo / etc");
}
