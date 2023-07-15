#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-8b0ba02338.
#

include("compat.inc");

if (description)
{
  script_id(131202);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/09");

  script_cve_id("CVE-2019-18887", "CVE-2019-18888", "CVE-2019-18889");
  script_xref(name:"FEDORA", value:"2019-8b0ba02338");

  script_name(english:"Fedora 31 : php-symfony3 (2019-8b0ba02338)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 3.4.35** (2019-11-13)

  - bug #34344 [Console] Constant STDOUT might be undefined
    (nicolas-grekas)

  - security #cve-2019-18889 [Cache] forbid serializing
    AbstractAdapter and TagAwareAdapter instances
    (nicolas-grekas)

  - security #cve-2019-18888 [HttpFoundation] fix guessing
    mime-types of files with leading dash (nicolas-grekas)

  - security #cve-2019-18887 [HttpKernel] Use constant time
    comparison in UriSigner (stof)

----

**Version 3.4.34** (2019-11-11)

  - bug #34297 [DI] fix locators with numeric keys
    (nicolas-grekas)

  - bug #34282 [DI] Dont cache classes with missing parents
    (nicolas-grekas)

  - bug #34181 [Stopwatch] Fixed bug in getDuration when
    counting multiple ongoing periods (TimoBakx)

  - bug #34179 [Stopwatch] Fixed a bug in
    StopwatchEvent::getStartTime (TimoBakx)

  - bug #34203 [FrameworkBundle] [HttpKernel] fixed correct
    EOL and EOM month (erics86)

----

**Version 3.4.33** (2019-11-01)

  - bug #33998 [Config] Disable default alphabet sorting in
    glob function due of unstable sort (hurricane-voronin)

  - bug #34144 [Serializer] Improve messages for unexpected
    resources values (fancyweb)

  - bug #34080 [SecurityBundle] correct types for default
    arguments for firewall configs (shieldo)

  - bug #33999 [Form] Make sure to collect child forms
    created on *_SET_DATA events (yceruto)

  - bug #34021 [TwigBridge] do not render errors for
    checkboxes twice (xabbuh)

  - bug #34041 [HttpKernel] fix wrong removal of the just
    generated container dir (nicolas-grekas)

  - bug #34023 [Dotenv] allow LF in single-quoted strings
    (nicolas-grekas)

  - bug #33818 [Yaml] Throw exception for tagged invalid
    inline elements (gharlan)

  - bug #33948 [PropertyInfo] Respect property name case
    when guessing from public method name (antograssiot)

  - bug #33962 [Cache] fixed TagAwareAdapter returning
    invalid cache (v-m-i)

  - bug #33965 [HttpFoundation] Add plus character `+` to
    legal mime subtype (ilzrv)

  - bug #32943 [Dotenv] search variable values in ENV first
    then env file (soufianZantar)

  - bug #33943 [VarDumper] fix resetting the 'bold' state in
    CliDumper (nicolas-grekas)

----

**Version 3.4.32** (2019-10-07)

  - bug #33834 [Validator] Fix ValidValidator group
    cascading usage (fancyweb)

  - bug #33841 [VarDumper] fix dumping uninitialized
    SplFileInfo (nicolas-grekas)

  - bug #33799 [Security]: Don't let falsy usernames slip
    through impersonation (j4nr6n)

  - bug #33814 [HttpFoundation] Check if data passed to
    SessionBagProxy::initialize is an array (mynameisbogdan)

  - bug #33805 [FrameworkBundle] Fix wrong returned status
    code in ConfigDebugCommand (jschaedl)

  - bug #33781 [AnnotationCacheWarmer] add
    RedirectController to annotation cache (jenschude)

  - bug #33777 Fix the :only-of-type pseudo class selector
    (jakzal)

  - bug #32051 [Serializer] Add CsvEncoder tests for PHP 7.4
    (ro0NL)

  - feature #33776 Copy phpunit.xsd to a predictable path
    (julienfalque)

  - bug #33759 [Security/Http] fix parsing X509 emailAddress
    (nicolas-grekas)

  - bug #33733 [Serializer] fix denormalization of
    string-arrays with only one element (mkrauser)

  - bug #33754 [Cache] fix known tag versions ttl check
    (SwenVanZanten)

  - bug #33646 [HttpFoundation] allow additinal characters
    in not raw cookies (marie)

  - bug #33748 [Console] Do not include hidden commands in
    suggested alternatives (m-vo)

  - bug #33625 [DependencyInjection] Fix wrong exception
    when service is synthetic (k0d3r1s)

  - bug #32522 [Validator] Accept underscores in the URL
    validator, as the URL will load (battye)

  - bug #32437 Fix toolbar load when GET params are present
    in '_wdt' route (Molkobain)

  - bug #32925 [Translation] Collect original locale in case
    of fallback translation (digilist)

  - bug #31198 [FrameworkBundle] Fix framework bundle lock
    configuration not working as expected (HypeMC)

  - bug #33719 [Cache] dont override native Memcached
    options (nicolas-grekas)

  - bug #33675 [PhpUnit] Fix usleep mock return value
    (fabpot)

  - bug #33618 fix tests depending on other components'
    tests (xabbuh)

  - bug #33626 [PropertyInfo] ensure compatibility with type
    resolver 0.5 (xabbuh)

  - bug #33620 [Twig] Fix Twig config extra keys (fabpot)

  - bug #33571 [Inflector] add support 'see' to 'ee' for
    singularize 'fees' to 'fee' (maxhelias)

  - bug #32763 [Console] Get dimensions from stty on windows
    if possible (rtek)

  - bug #33518 [Yaml] don't dump a scalar tag value on its
    own line (xabbuh)

  - bug #32818 [HttpKernel] Fix getFileLinkFormat() to avoid
    returning the wrong URL in Profiler (Arman-Hosseini)

  - bug #33487 [HttpKernel] Fix Apache mod_expires Session
    Cache-Control issue (pbowyer)

  - bug #33439 [Validator] Sync string to date behavior and
    throw a better exception (fancyweb)

  - bug #32903 [PHPUnit Bridge] Avoid registering listener
    twice (alexpott)

  - bug #33402 [Finder] Prevent unintentional file locks in
    Windows (jspringe)

  - bug #33396 Fix #33395 PHP 5.3 compatibility
    (kylekatarnls)

  - bug #33385 [Console] allow Command::getName() to return
    null (nicolas-grekas)

  - bug #33353 Return null as Expire header if it was set to
    null (danrot)

  - bug #33382 [ProxyManager] remove
    ProxiedMethodReturnExpression polyfill (nicolas-grekas)

  - bug #33377 [Yaml] fix dumping not inlined scalar tag
    values (xabbuh)

----

**Version 3.4.31** (2019-08-26)

  - bug #33335 [DependencyInjection] Fixed the
    `getServiceIds` implementation to always return aliases
    (pdommelen)

  - bug #33244 [Router] Fix TraceableUrlMatcher behaviour
    with trailing slash (Xavier Leune)

  - bug #33172 [Console] fixed a PHP notice when there is no
    function in the stack trace of an Exception (fabpot)

  - bug #33157 Fix getMaxFilesize() returning zero (ausi)

  - bug #33139 [Intl] Cleanup unused language aliases entry
    (ro0NL)

  - bug #33066 [Serializer] Fix negative DateInterval
    (jderusse)

  - bug #33033 [Lock] consistently throw NotSupportException
    (xabbuh)

  - bug #32516 [FrameworkBundle][Config] Ignore exceptions
    thrown during reflection classes autoload (fancyweb)

  - bug #32981 Fix tests/code for php 7.4 (jderusse)

  - bug #32992 [ProxyManagerBridge] Polyfill for
    unmaintained version (jderusse)

  - bug #32933 [PhpUnitBridge] fixed PHPUnit 8.3
    compatibility: method handleError was renamed to
    __invoke (karser)

  - bug #32947 [Intl] Support DateTimeInterface in
    IntlDateFormatter::format (pierredup)

  - bug #32838 [FrameworkBundle] Detect indirect env vars in
    routing (ro0NL)

  - bug #32918 [Intl] Order alpha2 to alpha3 mapping (ro0NL)

  - bug #32902 [PhpUnitBridge] Allow sutFqcnResolver to
    return array (VincentLanglet)

  - bug #32682 [HttpFoundation] Revert getClientIp @return
    docblock (ossinkine)

  - bug #32910 [Yaml] PHP-8: Uncaught TypeError: abs()
    expects parameter 1 to be int or float, string given
    (Aleksandr Dankovtsev)

  - bug #32870 #32853 Check if $this->parameters is array.
    (ABGEO07)

  - bug #32868 [PhpUnitBridge] Allow symfony/phpunit-bridge
    > 4.2 to be installed with phpunit 4.8 (jderusse)

  - bug #32767 [Yaml] fix comment in multi line value
    (soufianZantar)

  - bug #32790 [HttpFoundation] Fix `getMaxFilesize`
    (bennyborn)

  - bug #32796 [Cache] fix warning on PHP 7.4 (jpauli)

  - bug #32806 [Console] fix warning on PHP 7.4 (rez1dent3)

  - bug #32809 Don't add object-value of static properties
    in the signature of container metadata-cache (arjenm)

  - bug #30096 [DI] Fix dumping Doctrine-like service graphs
    (bis) (weaverryan, nicolas-grekas)

  - bug #32799 [HttpKernel] do not stopwatch sections when
    profiler is disabled (Tobion)

----

**Packaging changes**

  - One distinct autoloader for each component.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-8b0ba02338"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony3 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"php-symfony3-3.4.35-2.fc31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony3");
}
