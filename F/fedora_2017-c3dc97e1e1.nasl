#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-c3dc97e1e1.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96574);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-10033", "CVE-2016-10045", "CVE-2017-5223");
  script_xref(name:"FEDORA", value:"2017-c3dc97e1e1");

  script_name(english:"Fedora 24 : php-PHPMailer (2017-c3dc97e1e1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 5.2.22** (January 5th 2017)

  - **SECURITY** Fix
    [CVE-2017-5223](https://web.nvd.nist.gov/view/vuln/detai
    l?vulnId=CVE-2017-5223), local file disclosure
    vulnerability if content passed to `msgHTML()` is
    sourced from unfiltered user input. Reported by
    Yongxiang Li of Asiasecurity. The fix for this means
    that calls to `msgHTML()` without a `$basedir` will not
    import images with relative URLs, and relative URLs
    containing `..` will be ignored.

  - Add simple contact form example

  - Emoji in test content

----

**Version 5.2.21** (December 28th 2016)

  - Fix missed number update in version file - no functional
    changes

----

**Version 5.2.20** (December 28th 2016)

  - **SECURITY** Critical security update for CVE-2016-10045
    please update now! Thanks to [Dawid
    Golunski](https://legalhackers.com) and Paul Buonopane
    (Zenexer).

----

** Version 5.2.19** (December 26th 2016)

  - Minor cleanup

** Version 5.2.18** (December 24th 2016)

  - **SECURITY** Critical security update for CVE-2016-10033
    please update now! Thanks to [Dawid
    Golunski](https://legalhackers.com).

  - Add ability to extract the SMTP transaction ID from some
    common SMTP success messages

  - Minor documentation tweaks

** Version 5.2.17** (December 9th 2016)

  - This is officially the last feature release of 5.2.
    Security fixes only from now on; use PHPMailer 6.0!

  - Allow DKIM private key to be provided as a string

  - Provide mechanism to allow overriding of boundary and
    message ID creation

  - Improve Brazilian Portuguese, Spanish, Swedish,
    Romanian, and German translations

  - PHP 7.1 support for Travis-CI

  - Fix some language codes

  - Add security notices

  - Improve DKIM compatibility in older PHP versions

  - Improve trapping and capture of SMTP connection errors

  - Improve passthrough of error levels for debug output

  - PHPDoc cleanup

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-c3dc97e1e1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://legalhackers.com"
  );
  # https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5223
  script_set_attribute(
    attribute:"see_also",
    value:"https://nvd.nist.gov/vuln/detail/CVE-2017-5223"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-PHPMailer package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHPMailer Sendmail Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-PHPMailer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"php-PHPMailer-5.2.22-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-PHPMailer");
}
