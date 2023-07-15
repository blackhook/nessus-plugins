#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-207.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106998);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-3144");

  script_name(english:"openSUSE Security Update : dhcp (openSUSE-2018-207)");
  script_summary(english:"Check for the openSUSE-2018-207 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for dhcp fixes several issues.

This security issue was fixed :

  - CVE-2017-3144: OMAPI code didn't free socket descriptors
    when empty message is received allowing DoS
    (bsc#1076119).

These non-security issues were fixed :

  - Optimized if and when DNS client context and ports are
    initted (bsc#1073935)

  - Relax permission of dhclient-script for libguestfs
    (bsc#987170)

  - Modify dhclient-script to handle static route updates
    (bsc#1023415).

  - Use only the 12 least significant bits of an inbound
    packet's TCI value as the VLAN ID to fix some packages
    being wrongly discarded by the Linux packet filter.
    (bsc#1059061)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1023415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987170"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-relay-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dhcp-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE42.3", reference:"dhcp-4.3.3-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dhcp-client-4.3.3-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dhcp-client-debuginfo-4.3.3-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dhcp-debuginfo-4.3.3-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dhcp-debugsource-4.3.3-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dhcp-devel-4.3.3-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dhcp-relay-4.3.3-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dhcp-relay-debuginfo-4.3.3-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dhcp-server-4.3.3-11.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dhcp-server-debuginfo-4.3.3-11.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp / dhcp-client / dhcp-client-debuginfo / dhcp-debuginfo / etc");
}
