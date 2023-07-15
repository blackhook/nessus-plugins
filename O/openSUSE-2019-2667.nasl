#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2667.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(131992);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/16");

  script_cve_id("CVE-2019-5163", "CVE-2019-5164");

  script_name(english:"openSUSE Security Update : shadowsocks-libev (openSUSE-2019-2667)");
  script_summary(english:"Check for the openSUSE-2019-2667 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for shadowsocks-libev fixes the following issues :

  - Update version to 3.3.3

  - Refine the handling of suspicious connections.

  - Fix exploitable denial-of-service vulnerability exists
    in the UDPRelay functionality (boo#1158251,
    CVE-2019-5163)

  - Fix code execution vulnerability in the ss-manager
    binary (boo#1158365, CVE-2019-5164)

  - Refine the handling of fragment request.

  - Fix a high CPU bug introduced in 3.3.0. (#2449)

  - Enlarge the socket buffer size to 16KB.

  - Fix the empty list bug in ss-manager.

  - Fix the IPv6 address parser.

  - Fix a bug of port parser.

  - Fix a crash with MinGW.

  - Refine SIP003 plugin interface.

  - Remove connection timeout from all clients.

  - Fix the alignment bug again.

  - Fix a bug on 32-bit arch.

  - Add TCP fast open support to ss-tunnel by @PantherJohn."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158365"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected shadowsocks-libev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libshadowsocks-libev2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libshadowsocks-libev2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadowsocks-libev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadowsocks-libev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadowsocks-libev-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:shadowsocks-libev-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libshadowsocks-libev2-3.3.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libshadowsocks-libev2-debuginfo-3.3.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"shadowsocks-libev-3.3.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"shadowsocks-libev-debuginfo-3.3.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"shadowsocks-libev-debugsource-3.3.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"shadowsocks-libev-devel-3.3.3-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libshadowsocks-libev2 / libshadowsocks-libev2-debuginfo / etc");
}
