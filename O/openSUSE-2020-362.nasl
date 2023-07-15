#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-362.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(134755);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/24");

  script_cve_id("CVE-2018-11354", "CVE-2018-11355", "CVE-2018-11356", "CVE-2018-11357", "CVE-2018-11358", "CVE-2018-11359", "CVE-2018-11360", "CVE-2018-11361", "CVE-2018-11362", "CVE-2018-12086", "CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342", "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14367", "CVE-2018-14368", "CVE-2018-14369", "CVE-2018-14370", "CVE-2018-16056", "CVE-2018-16057", "CVE-2018-16058", "CVE-2018-18225", "CVE-2018-18226", "CVE-2018-18227", "CVE-2018-19622", "CVE-2018-19623", "CVE-2018-19624", "CVE-2018-19625", "CVE-2018-19626", "CVE-2018-19627", "CVE-2018-19628", "CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10896", "CVE-2019-10897", "CVE-2019-10898", "CVE-2019-10899", "CVE-2019-10900", "CVE-2019-10901", "CVE-2019-10902", "CVE-2019-10903", "CVE-2019-13619", "CVE-2019-16319", "CVE-2019-19553", "CVE-2019-5716", "CVE-2019-5717", "CVE-2019-5718", "CVE-2019-5719", "CVE-2019-5721", "CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214", "CVE-2020-7044", "CVE-2020-9428", "CVE-2020-9429", "CVE-2020-9430", "CVE-2020-9431");

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2020-362)");
  script_summary(english:"Check for the openSUSE-2020-362 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark and libmaxminddb fixes the following 
issues :

Update wireshark to new major version 3.2.2 and introduce libmaxminddb
for GeoIP support (bsc#1156288).

New features include :

  - Added support for 111 new protocols, including
    WireGuard, LoRaWAN, TPM 2.0, 802.11ax and QUIC

  - Improved support for existing protocols, like HTTP/2

  - Improved analytics and usability functionalities

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1127370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1165710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957624"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmaxminddb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmaxminddb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmaxminddb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmaxminddb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmaxminddb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmaxminddb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspandsp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspandsp2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspandsp2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libspandsp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwireshark13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwireshark13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwiretap10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwiretap10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsutil11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsutil11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mmdblookup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mmdblookup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spandsp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spandsp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libmaxminddb-debugsource-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmaxminddb-devel-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmaxminddb0-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmaxminddb0-debuginfo-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libspandsp2-0.0.6-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libspandsp2-debuginfo-0.0.6-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwireshark13-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwireshark13-debuginfo-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwiretap10-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwiretap10-debuginfo-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwsutil11-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwsutil11-debuginfo-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mmdblookup-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mmdblookup-debuginfo-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"spandsp-debugsource-0.0.6-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"spandsp-devel-0.0.6-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-debuginfo-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-debugsource-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-devel-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-ui-qt-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-ui-qt-debuginfo-3.2.2-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libmaxminddb0-32bit-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libmaxminddb0-32bit-debuginfo-1.4.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libspandsp2-32bit-0.0.6-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libspandsp2-32bit-debuginfo-0.0.6-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmaxminddb-debugsource / libmaxminddb-devel / libmaxminddb0 / etc");
}
