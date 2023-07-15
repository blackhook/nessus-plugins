#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-629.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149603);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-21201",
    "CVE-2021-21202",
    "CVE-2021-21203",
    "CVE-2021-21204",
    "CVE-2021-21205",
    "CVE-2021-21207",
    "CVE-2021-21208",
    "CVE-2021-21209",
    "CVE-2021-21210",
    "CVE-2021-21211",
    "CVE-2021-21212",
    "CVE-2021-21213",
    "CVE-2021-21221",
    "CVE-2021-21222",
    "CVE-2021-21223",
    "CVE-2021-21224",
    "CVE-2021-21225",
    "CVE-2021-21226",
    "CVE-2021-21227",
    "CVE-2021-21228",
    "CVE-2021-21229",
    "CVE-2021-21230",
    "CVE-2021-21231",
    "CVE-2021-21232",
    "CVE-2021-21233"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2021-629)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for chromium fixes the following issues :

  - Chromium was updated to 90.0.4430.93
    (boo#1184764,boo#1185047,boo#1185398)

  - CVE-2021-21227: Insufficient data validation in V8. 

  - CVE-2021-21232: Use after free in Dev Tools. 

  - CVE-2021-21233: Heap buffer overflow in ANGLE.

  - CVE-2021-21228: Insufficient policy enforcement in
    extensions.

  - CVE-2021-21229: Incorrect security UI in downloads.

  - CVE-2021-21230: Type Confusion in V8. 

  - CVE-2021-21231: Insufficient data validation in V8.

  - CVE-2021-21222: Heap buffer overflow in V8

  - CVE-2021-21223: Integer overflow in Mojo

  - CVE-2021-21224: Type Confusion in V8

  - CVE-2021-21225: Out of bounds memory access in V8

  - CVE-2021-21226: Use after free in navigation

  - CVE-2021-21201: Use after free in permissions

  - CVE-2021-21202: Use after free in extensions

  - CVE-2021-21203: Use after free in Blink

  - CVE-2021-21204: Use after free in Blink

  - CVE-2021-21205: Insufficient policy enforcement in
    navigation

  - CVE-2021-21221: Insufficient validation of untrusted
    input in Mojo

  - CVE-2021-21207: Use after free in IndexedDB

  - CVE-2021-21208: Insufficient data validation in QR
    scanner

  - CVE-2021-21209: Inappropriate implementation in storage

  - CVE-2021-21210: Inappropriate implementation in Network

  - CVE-2021-21211: Inappropriate implementation in
    Navigatio 

  - CVE-2021-21212: Incorrect security UI in Network Config
    UI

  - CVE-2021-21213: Use after free in WebMIDI");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=11845047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185398");
  script_set_attribute(attribute:"solution", value:
"Update the affected Chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21233");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-90.0.4430.93-lp152.2.89.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-debuginfo-90.0.4430.93-lp152.2.89.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-90.0.4430.93-lp152.2.89.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debuginfo-90.0.4430.93-lp152.2.89.1", allowmaj:TRUE) ) flag++;

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
