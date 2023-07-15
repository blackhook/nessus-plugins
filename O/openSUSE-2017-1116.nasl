#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1116.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103623);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493", "CVE-2017-14494", "CVE-2017-14495", "CVE-2017-14496");
  script_xref(name:"IAVA", value:"2017-A-0284-S");

  script_name(english:"openSUSE Security Update : dnsmasq (openSUSE-2017-1116)");
  script_summary(english:"Check for the openSUSE-2017-1116 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dnsmasq fixes the following security issues :

  - CVE-2017-14491: 2 byte heap based overflow.
    [bsc#1060354]

  - CVE-2017-14492: heap based overflow. [bsc#1060355]

  - CVE-2017-14493: stack based overflow. [bsc#1060360]

  - CVE-2017-14494: DHCP - info leak. [bsc#1060361]

  - CVE-2017-14495: DNS - OOM DoS. [bsc#1060362]

  - CVE-2017-14496: DNS - DoS Integer underflow.
    [bsc#1060364]

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060364"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dnsmasq packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dnsmasq-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE42.2", reference:"dnsmasq-2.78-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dnsmasq-debuginfo-2.78-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dnsmasq-debugsource-2.78-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dnsmasq-utils-2.78-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"dnsmasq-utils-debuginfo-2.78-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dnsmasq-2.78-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dnsmasq-debuginfo-2.78-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dnsmasq-debugsource-2.78-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dnsmasq-utils-2.78-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dnsmasq-utils-debuginfo-2.78-13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dnsmasq / dnsmasq-debuginfo / dnsmasq-debugsource / dnsmasq-utils / etc");
}
