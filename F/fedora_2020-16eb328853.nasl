#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-16eb328853.
#

include("compat.inc");

if (description)
{
  script_id(140546);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/16");

  script_cve_id("CVE-2020-15094");
  script_xref(name:"FEDORA", value:"2020-16eb328853");

  script_name(english:"Fedora 32 : php-symfony4 (2020-16eb328853)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"**Version 4.4.13** (2020-09-02)

  - security **CVE-2020-15094** Remove headers with internal
    meaning from HttpClient responses (mpdude)

  - bug #38024 [Console] Fix undefined index for
    inconsistent command name definition (chalasr)

  - bug #38023 [DI] fix inlining of non-shared services
    (nicolas-grekas)

  - bug #38020 [PhpUnitBridge] swallow deprecations (xabbuh)

  - bug #38010 [Cache] Psr16Cache does not handle Proxy
    cache items (alex-dev)

  - bug #37937 [Serializer] fixed fix encoding of cache keys
    with anonymous classes (michaelzangerle)

----

**Version 4.4.12** (2020-08-31)

  - bug #37966 [HttpClient][MockHttpClient][DX] Throw when
    the response factory callable does not return a valid
    response (fancyweb)

  - bug #37971 [PropertyInfo] Backport support for typed
    properties (PHP 7.4) (dunglas)

  - bug #37970 [PhpUnitBridge] Polyfill new phpunit 9.1
    assertions (phpfour)

  - bug #37960 [PhpUnit] Add polyfill for
    assertMatchesRegularExpression() (dunglas)

  - bug #37949 [Yaml] fix more numeric cases changing in PHP
    8 (xabbuh)

  - bug #37921 [Yaml] account for is_numeric() behavior
    changes in PHP 8 (xabbuh)

  - bug #37912 [ExpressionLanguage] fix passing arguments to
    call_user_func_array() on PHP 8 (xabbuh)

  - bug #37907 [Messenger] stop using the deprecated schema
    synchronizer API (xabbuh)

  - bug #37900 [Mailer] Fixed mandrill api header structure
    (wulff)

  - bug #37888 [Mailer] Reorder headers used to determine
    Sender (cvmiert)

  - bug #37872 [Sendgrid-Mailer] Fixed envelope recipients
    on sendgridApiTransport (arendjantetteroo)

  - bug #37860 [Serializer][ClassDiscriminatorMapping] Fix
    getMappedObjectType() when a discriminator child extends
    another one (fancyweb)

  - bug #37853 [Validator] ensure that the validator is a
    mock object for backwards-compatibility (xabbuh)

  - bug #36340 [Serializer] Fix configuration of the cache
    key (dunglas)

  - bug #36810 [Messenger] Do not stack retry stamp
    (jderusse)

  - bug #37849 [FrameworkBundle] Add missing mailer
    transports in xsd (l-vo)

  - bug #37586 [ErrorHandler][DebugClassLoader] Add mixed
    and static return types support (fancyweb)

  - bug #37845 [Serializer] Fix variadic support when using
    type hints (fabpot)

  - bug #37841 [VarDumper] Backport handler lock when using
    VAR_DUMPER_FORMAT (ogizanagi)

  - bug #37725 [Form] Fix Guess phpdoc return type
    (franmomu)

  - bug #37771 Use PHPUnit 9.3 on php 8 (derrabus)

  - bug #36140 [Validator] Add BC layer for
    notInRangeMessage when min and max are set (l-vo)

  - bug #35843 [Validator] Add target guards for Composite
    nested constraints (ogizanagi)

  - bug #37803 Fix for issue #37681 (Rav)

  - bug #37744 [Yaml] Fix for #36624; Allow PHP constant as
    first key in block (jnye)

  - bug #37767 [Form] fix mapping errors from unmapped forms
    (xabbuh)

  - bug #37731 [Console] Table: support cells with newlines
    after a cell with colspan >= 2 (GMTA)

  - bug #37791 Fix redis connect with empty password
    (alexander-schranz)

  - bug #37790 Fix deprecated libxml_disable_entity_loader
    (fabpot)

  - bug #37763 Fix deprecated libxml_disable_entity_loader
    (jderusse)

  - bug #37774 [Console] Make sure we pass a numeric array
    of arguments to call_user_func_array() (derrabus)

  - bug #37729 [FrameworkBundle] fail properly when the
    required service is not defined (xabbuh)

  - bug #37701 [Serializer] Fix that it will never reach
    DOMNode (TNAJanssen)

  - bug #37671 [Cache] fix saving no-expiry items with
    ArrayAdapter (philipp-kolesnikov)

  - bug #37102 [WebProfilerBundle] Fix error with custom
    function and web profiler routing tab (JakeFr)

  - bug #37560 [Finder] Fix GitIgnore parser when dealing
    with (sub)directories and take order of lines into
    account (Jeroeny)

  - bug #37700 [VarDumper] Improve previous fix on light
    array coloration (l-vo)

  - bug #37705 [Mailer] Added the missing reset tag to
    mailer.logger_message_listener (vudaltsov)

  - bug #37697 [Messenger] reduce column length for MySQL
    5.6 compatibility (xabbuh)

----

  - fix path of doctrine/persistence 2 in autoloader

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-16eb328853"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected php-symfony4 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"php-symfony4-4.4.13-1.fc32")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony4");
}
