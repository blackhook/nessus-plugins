#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-980.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102834);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-1531", "CVE-2016-9963", "CVE-2017-1000369");

  script_name(english:"openSUSE Security Update : exim (openSUSE-2017-980) (Stack Clash)");
  script_summary(english:"Check for the openSUSE-2017-980 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for exim fixes the following issues :

Changes in exim :

  - specify users with ref:mail, to make them dynamic.
    (boo#1046971)

  - CVE-2017-1000369: Fixed memory leaks that could be
    exploited to 'stack crash' local privilege escalation
    (boo#1044692)

  - Require user(mail) group(mail) to meet new users
    handling in TW.

  - Prerequire permissions (fixes rpmlint).

  - conditionally disable DANE on SuSE versions with OpenSSL
    < 1.0

  - CVE-2016-1531: when installed setuid root, allows local
    users to gain privileges via the perl_startup argument. 

  - CVE-2016-9963: DKIM information leakage (boo#1015930)



  - Makefile tuning :

  + add sqlite support

  + disable WITH_OLD_DEMIME

  + enable AUTH_CYRUS_SASL

  + enable AUTH_TLS

  + enable SYSLOG_LONG_LINES

  + enable SUPPORT_PAM

  + MAX_NAMED_LIST=64

  + enable EXPERIMENTAL_DMARC

  + enable EXPERIMENTAL_EVENT

  + enable EXPERIMENTAL_PROXY

  + enable EXPERIMENTAL_CERTNAMES

  + enable EXPERIMENTAL_DSN

  + enable EXPERIMENTAL_DANE

  + enable EXPERIMENTAL_SOCKS

  + enable EXPERIMENTAL_INTERNATIONAL"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046971"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected exim packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:exim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eximstats-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/30");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"exim-4.86.2-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"exim-debuginfo-4.86.2-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"exim-debugsource-4.86.2-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"eximon-4.86.2-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"eximon-debuginfo-4.86.2-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"eximstats-html-4.86.2-10.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"exim-4.86.2-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"exim-debuginfo-4.86.2-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"exim-debugsource-4.86.2-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"eximon-4.86.2-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"eximon-debuginfo-4.86.2-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"eximstats-html-4.86.2-14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-debuginfo / exim-debugsource / eximon / etc");
}
