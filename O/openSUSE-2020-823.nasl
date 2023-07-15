#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-823.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138688);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-6463", "CVE-2020-6465", "CVE-2020-6466", "CVE-2020-6467", "CVE-2020-6468", "CVE-2020-6469", "CVE-2020-6470", "CVE-2020-6471", "CVE-2020-6472", "CVE-2020-6473", "CVE-2020-6474", "CVE-2020-6475", "CVE-2020-6476", "CVE-2020-6477", "CVE-2020-6478", "CVE-2020-6479", "CVE-2020-6480", "CVE-2020-6481", "CVE-2020-6482", "CVE-2020-6483", "CVE-2020-6484", "CVE-2020-6485", "CVE-2020-6486", "CVE-2020-6487", "CVE-2020-6488", "CVE-2020-6489", "CVE-2020-6490", "CVE-2020-6491", "CVE-2020-6493", "CVE-2020-6494", "CVE-2020-6495", "CVE-2020-6496");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2020-823)");
  script_summary(english:"Check for the openSUSE-2020-823 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for chromium fixes the following issues :

Chromium was updated to 83.0.4103.97 (boo#1171910,bsc#1172496) :

  - CVE-2020-6463: Use after free in ANGLE (boo#1170107
    boo#1171975).

  - CVE-2020-6465: Use after free in reader mode. Reported
    by Woojin Oh(@pwn_expoit) of STEALIEN on 2020-04-21

  - CVE-2020-6466: Use after free in media. Reported by Zhe
    Jin from cdsrc of Qihoo 360 on 2020-04-26

  - CVE-2020-6467: Use after free in WebRTC. Reported by
    ZhanJia Song on 2020-04-06

  - CVE-2020-6468: Type Confusion in V8. Reported by Chris
    Salls and Jake Corina of Seaside Security, Chani Jindal
    of Shellphish on 2020-04-30

  - CVE-2020-6469: Insufficient policy enforcement in
    developer tools. Reported by David Erceg on 2020-04-02

  - CVE-2020-6470: Insufficient validation of untrusted
    input in clipboard. Reported by Micha&#x142; Bentkowski
    of Securitum on 2020-03-30

  - CVE-2020-6471: Insufficient policy enforcement in
    developer tools. Reported by David Erceg on 2020-03-08

  - CVE-2020-6472: Insufficient policy enforcement in
    developer tools. Reported by David Erceg on 2020-03-25

  - CVE-2020-6473: Insufficient policy enforcement in Blink.
    Reported by Soroush Karami and Panagiotis Ilia on
    2020-02-06

  - CVE-2020-6474: Use after free in Blink. Reported by Zhe
    Jin from cdsrc of Qihoo 360 on 2020-03-07

  - CVE-2020-6475: Incorrect security UI in full screen.
    Reported by Khalil Zhani on 2019-10-31

  - CVE-2020-6476: Insufficient policy enforcement in tab
    strip. Reported by Alexandre Le Borgne on 2019-12-18

  - CVE-2020-6477: Inappropriate implementation in
    installer. Reported by RACK911 Labs on 2019-03-26

  - CVE-2020-6478: Inappropriate implementation in full
    screen. Reported by Khalil Zhani on 2019-12-24

  - CVE-2020-6479: Inappropriate implementation in sharing.
    Reported by Zhong Zhaochen of andsecurity.cn on
    2020-01-14

  - CVE-2020-6480: Insufficient policy enforcement in
    enterprise. Reported by Marvin Witt on 2020-02-21

  - CVE-2020-6481: Insufficient policy enforcement in URL
    formatting. Reported by Rayyan Bijoora on 2020-04-07

  - CVE-2020-6482: Insufficient policy enforcement in
    developer tools. Reported by Abdulrahman Alqabandi
    (@qab) on 2017-12-17

  - CVE-2020-6483: Insufficient policy enforcement in
    payments. Reported by Jun Kokatsu, Microsoft Browser
    Vulnerability Research on 2019-05-23

  - CVE-2020-6484: Insufficient data validation in
    ChromeDriver. Reported by Artem Zinenko on 2020-01-26

  - CVE-2020-6485: Insufficient data validation in media
    router. Reported by Sergei Glazunov of Google Project
    Zero on 2020-01-30

  - CVE-2020-6486: Insufficient policy enforcement in
    navigations. Reported by David Erceg on 2020-02-24

  - CVE-2020-6487: Insufficient policy enforcement in
    downloads. Reported by Jun Kokatsu (@shhnjk) on
    2015-10-06

  - CVE-2020-6488: Insufficient policy enforcement in
    downloads. Reported by David Erceg on 2020-01-21

  - CVE-2020-6489: Inappropriate implementation in developer
    tools. Reported by @lovasoa (Ophir LOJKINE) on
    2020-02-10

  - CVE-2020-6490: Insufficient data validation in loader.
    Reported by Twitter on 2019-12-19

  - CVE-2020-6491: Incorrect security UI in site
    information. Reported by Sultan Haikal M.A on 2020-02-07

  - CVE-2020-6493: Use after free in WebAuthentication.

  - CVE-2020-6494: Incorrect security UI in payments.

  - CVE-2020-6495: Insufficient policy enforcement in
    developer tools.

  - CVE-2020-6496: Use after free in payments."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172496"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6496");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-83.0.4103.97-lp151.2.96.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-83.0.4103.97-lp151.2.96.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-83.0.4103.97-lp151.2.96.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-83.0.4103.97-lp151.2.96.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debugsource-83.0.4103.97-lp151.2.96.1", allowmaj:TRUE) ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
