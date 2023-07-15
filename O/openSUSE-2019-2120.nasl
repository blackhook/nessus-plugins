#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2120.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(128671);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-16843",
    "CVE-2018-16844",
    "CVE-2018-16845",
    "CVE-2019-9511",
    "CVE-2019-9513",
    "CVE-2019-9516"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"openSUSE Security Update : nginx (openSUSE-2019-2120) (0-Length Headers Leak) (Data Dribble) (Resource Loop)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for nginx fixes the following issues :

Security issues fixed :

  - CVE-2019-9511: Fixed a denial of service by manipulating
    the window size and stream prioritization (bsc#1145579).

  - CVE-2019-9513: Fixed a denial of service caused by
    resource loops (bsc#1145580).

  - CVE-2019-9516: Fixed a denial of service caused by
    header leaks (bsc#1145582).

  - CVE-2018-16845: Fixed denial of service and memory
    disclosure via mp4 module (bsc#1115015).

  - CVE-2018-16843: Fixed excessive memory consumption in
    HTTP/2 implementation (bsc#1115022).

  - CVE-2018-16844: Fixed excessive CPU usage via flaw in
    HTTP/2 implementation (bsc#1115025).

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145582");
  script_set_attribute(attribute:"solution", value:
"Update the affected nginx packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16845");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-plugin-nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"nginx-1.14.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nginx-debuginfo-1.14.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nginx-debugsource-1.14.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nginx-source-1.14.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-plugin-nginx-1.14.2-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx / nginx-debuginfo / nginx-debugsource / nginx-source / etc");
}
