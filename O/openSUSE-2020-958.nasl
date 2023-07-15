#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-958.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138739);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/27");

  script_cve_id("CVE-2020-8024");

  script_name(english:"openSUSE Security Update : hylafax+ (openSUSE-2020-958)");
  script_summary(english:"Check for the openSUSE-2020-958 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for hylafax+ fixes the following issues :

Security issue fixed :

  - CVE-2020-8024 boo#1172731 

hylafax+ was updated to version 7.0.2 :

  - change FIXEDWIDTH default to better accommodate
    auto-rotation (13 Dec 2019)

  - prevent SSL_accept() from blocking (5 Dec 2019)

  - support libtiff v4.1 (5 Dec 2019)

  - fix ignoremodembusy feature broken by ModemGroup limits
    feature (16 Nov 2019)

Version 7.0.1 :

  - create a client timeout setting and change the default
    from 60 to 3600 seconds (26 Sep 2019)

  - extend timeout for receiving ECM frames (21 Aug 2019)

  - fix timeout in Class 1 frame reception (5 Aug 2019)

  - improve Class 1 protocol handling when MaxRecvPages
    exceeded (31 Jul 2019)

  - fix ModemGroup limit default (11 Jul 2019)

  - fix recovery for SSL Fax write failures (6 Jun 2019)

Version 7.0.0 :

  - add LDAP features for compatibility with ActiveDirectory
    (25 Mar-1 Apr 2019)

  - fix recovery after SSL Fax 'accept failure' (18 Mar
    2019)

  - add TextFormat overstrike option and disable by default
    (6 Feb 2019)

  - fix the page size of cover sheets returned via notify (8
    Jan 2019)

  - fix or silence numerous compiler warnings (19, 22, 28
    Dec 2018)

  - fix pagehandling updating after a proxy has been used
    (7-8 Dec 2018)

  - add faxmail stderr output of RFC2047 decoding results (5
    Dec 2018)

  - fix faxmail handling of headers encoded with UTF-8 (4
    Dec 2018)

  - fix faxmail handling of base64-encoded text parts (4 Dec
    2018)

  - add SSL Fax support (9-26, 29 Nov; 11, 18, 25 Dec 2018;
    2, 7, 23 Jan 2019)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172731"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected hylafax+ packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hylafax+-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfaxutil7_0_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfaxutil7_0_2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"hylafax+-7.0.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"hylafax+-client-7.0.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"hylafax+-client-debuginfo-7.0.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"hylafax+-debuginfo-7.0.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"hylafax+-debugsource-7.0.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfaxutil7_0_2-7.0.2-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfaxutil7_0_2-debuginfo-7.0.2-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hylafax+ / hylafax+-client / hylafax+-client-debuginfo / etc");
}
