#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-832.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150248);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-21341",
    "CVE-2021-21342",
    "CVE-2021-21343",
    "CVE-2021-21344",
    "CVE-2021-21345",
    "CVE-2021-21346",
    "CVE-2021-21347",
    "CVE-2021-21348",
    "CVE-2021-21349",
    "CVE-2021-21350",
    "CVE-2021-21351"
  );

  script_name(english:"openSUSE Security Update : xstream (openSUSE-2021-832)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for xstream fixes the following issues :

  - Upgrade to 1.4.16

  - CVE-2021-21351: remote attacker to load and execute
    arbitrary code (bsc#1184796)

  - CVE-2021-21349: SSRF can lead to a remote attacker to
    request data from internal resources (bsc#1184797)

  - CVE-2021-21350: arbitrary code execution (bsc#1184380)

  - CVE-2021-21348: remote attacker could cause denial of
    service by consuming maximum CPU time (bsc#1184374)

  - CVE-2021-21347: remote attacker to load and execute
    arbitrary code from a remote host (bsc#1184378)

  - CVE-2021-21344: remote attacker could load and execute
    arbitrary code from a remote host (bsc#1184375)

  - CVE-2021-21342: server-side forgery (bsc#1184379)

  - CVE-2021-21341: remote attacker could cause a denial of
    service by allocating 100% CPU time (bsc#1184377)

  - CVE-2021-21346: remote attacker could load and execute
    arbitrary code (bsc#1184373)

  - CVE-2021-21345: remote attacker with sufficient rights
    could execute commands (bsc#1184372)

  - CVE-2021-21343: replace or inject objects, that result
    in the deletion of files on the local host (bsc#1184376)

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184797");
  script_set_attribute(attribute:"solution", value:
"Update the affected xstream packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21350");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21345");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream-benchmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream-parent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"xstream-1.4.16-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xstream-benchmark-1.4.16-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xstream-javadoc-1.4.16-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xstream-parent-1.4.16-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xstream / xstream-benchmark / xstream-javadoc / xstream-parent");
}
