#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-444.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109717);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-7158", "CVE-2018-7159", "CVE-2018-7160");

  script_name(english:"openSUSE Security Update : nodejs6 (openSUSE-2018-444)");
  script_summary(english:"Check for the openSUSE-2018-444 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nodejs6 fixes the following issues :

  - Fix some node-gyp permissions

  - New upstream LTS release 6.14.1 :

  - Security fixes :

  + CVE-2018-7160: Fix for inspector DNS rebinding
    vulnerability (bsc#1087463)

  + CVE-2018-7158: Fix for 'path' module regular expression
    denial of service (bsc#1087459)

  + CVE-2018-7159: Reject spaces in HTTP Content-Length
    header values (bsc#1087453)

  - New upstream LTS release 6.13.1 :

  - http,tls: better support for IPv6 addresses

  - console: added console.count() and console.clear()

  - crypto :

  + expose ECDH class

  + added cypto.randomFill() and crypto.randomFillSync()

  + warn on invalid authentication tag length

  - deps: upgrade libuv to 1.16.1

  - dgram: added socket.setMulticastInterface()

  - http: add agent.keepSocketAlive and agent.reuseSocket as to
allow overridable keep-alive behavior of Agent

  - lib: return this from net.Socket.end()

  - module: add builtinModules api that provides list of all
    builtin modules in Node

  - net: return this from getConnections()

  - promises: more robust stringification for unhandled
    rejections

  - repl: improve require() autocompletion

  - src :

  + add openssl-system-ca-path configure option

  + add --use-bundled-ca --use-openssl-ca check

  + add process.ppid

  - tls: accept lookup option for tls.connect()

  - tools,build: a new macOS installer!

  - url: WHATWG URL api support

  - util: add %i and %f formatting specifiers

  - remove any old manpage files in %pre from before
    update-alternatives were used to manage symlinks to
    these manpages.

  - Add Recommends and BuildRequire on python2 for npm.
    node-gyp requires this old version of python for now.
    This is only needed for binary modules.

  - even on recent codestreams there is no binutils gold on
    s390 only on s390x

  - New upstream LTS release 6.12.3 :

  - v8: profiler-related fixes

  - mostly documentation and test related changes

  - Enable CI tests in %check target

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087463"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");
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

if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-6.14.1-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-debuginfo-6.14.1-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-debugsource-6.14.1-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-devel-6.14.1-9.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"npm6-6.14.1-9.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs6 / nodejs6-debuginfo / nodejs6-debugsource / nodejs6-devel / etc");
}
