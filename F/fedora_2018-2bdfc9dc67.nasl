#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-2bdfc9dc67.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110949);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-16652");
  script_xref(name:"FEDORA", value:"2018-2bdfc9dc67");

  script_name(english:"Fedora 27 : php-symfony (2018-2bdfc9dc67)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 2.8.42 (2018-06-25)

  - bug #27669 [Filesystem] fix file lock on SunOS (fritzmg)

  - bug #27309 Fix surrogate not using original request
    (Toflar)

  - bug #27630 [Validator][Form] Remove BOM in some xlf
    files (gautierderuette)

  - bug #27591 [VarDumper] Fix dumping ArrayObject and
    ArrayIterator instances (nicolas-grekas)

  - bug #27581 Fix bad method call with guard authentication
    + session migration (weaverryan)

  - bug #27452 Avoid migration on stateless firewalls
    (weaverryan)

  - bug #27514 [Debug] Pass previous exception to
    FatalErrorException (pmontoya)

  - bug #26973 [HttpKernel] Set first trusted proxy as
    REMOTE_ADDR in InlineFragmentRenderer. (kmadejski)

  - bug #27303 [Process] Consider 'executable' suffixes
    first on Windows (sanmai)

  - bug #27297 Triggering RememberMe's loginFail() when
    token cannot be created (weaverryan)

  - bug #27366 [DI] never inline lazy services
    (nicolas-grekas)

## 2.8.41 (2018-05-25)

  - bug #27359 [HttpFoundation] Fix perf issue during
    MimeTypeGuesser intialization (nicolas-grekas)

  - security #cve-2018-11408 [SecurityBundle] Fail if
    security.http_utils cannot be configured

  - security #cve-2018-11406 clear CSRF tokens when the user
    is logged out

  - security #cve-2018-11385 Adding session authentication
    strategy to Guard to avoid session fixation

  - security #cve-2018-11385 Adding session strategy to ALL
    listeners to avoid *any* possible fixation

  - security #cve-2018-11386 [HttpFoundation] Break infinite
    loop in PdoSessionHandler when MySQL is in loose mode

## 2.8.40 (2018-05-21)

  - bug #26781 [Form] Fix precision of
    MoneyToLocalizedStringTransformer's divisions on
    transform() (syastrebov)

  - bug #27286 [Translation] Add Occitan plural rule
    (kylekatarnls)

  - bug #27246 Disallow invalid characters in session.name
    (ostrolucky)

  - bug #24805 [Security] Fix logout (MatTheCat)

  - bug #27141 [Process] Suppress warnings when open_basedir
    is non-empty (cbj4074)

  - bug #27250 [Session] limiting :key for GET_LOCK to 64
    chars (oleg-andreyev)

  - bug #27237 [Debug] Fix populating error_get_last() for
    handled silent errors (nicolas-grekas)

  - bug #27236 [Filesystem] Fix usages of error_get_last()
    (nicolas-grekas)

  - bug #27152 [HttpFoundation] use brace-style regex
    delimiters (xabbuh)

  - feature #24896 Add CODE_OF_CONDUCT.md (egircys)

## 2.8.39 (2018-04-30)

  - bug #27067 [HttpFoundation] Fix setting session-related
    ini settings (e-moe)

  - bug #27016 [Security][Guard]
    GuardAuthenticationProvider::authenticate cannot return
    null (biomedia-thomas)

  - bug #26831 [Bridge/Doctrine] count(): Parameter must be
    an array or an object that implements Countable
    (gpenverne)

  - bug #27044 [Security] Skip user checks if not
    implementing UserInterface (chalasr)

  - bug #26014 [Security] Fixed being logged out on failed
    attempt in guard (iltar)

  - bug #26910 Use new PHP7.2 functions in hasColorSupport
    (johnstevenson)

  - bug #26999 [VarDumper] Fix dumping of SplObjectStorage
    (corphi)

  - bug #25841 [DoctrineBridge] Fix bug when indexBy is meta
    key in PropertyInfo\DoctrineExtractor (insekticid)

  - bug #26886 Don't assume that file binary exists on *nix
    OS (teohhanhui)

  - bug #26643 Fix that ESI/SSI processing can turn a
    'private' response 'public' (mpdude)

  - bug #26932 [Form] Fixed trimming choice values
    (HeahDude)

  - bug #26875 [Console] Don't go past exact matches when
    autocompleting (nicolas-grekas)

  - bug #26823 [Validator] Fix LazyLoadingMetadataFactory
    with PSR6Cache for non classname if tested values isn't
    existing class (Pascal Montoya, pmontoya)

  - bug #26834 [Yaml] Throw parse error on unfinished inline
    map (nicolas-grekas)

## 2.8.38 (2018-04-06)

  - bug #26788 [Security] Load the user before pre/post auth
    checks when needed (chalasr)

  - bug #26774 [SecurityBundle] Add missing argument to
    security.authentication.provider.simple (i3or1s,
    chalasr)

  - bug #26763 [Finder] Remove duplicate slashes in
    filenames (helhum)

  - bug #26749 Add PHPDbg support to HTTP components
    (hkdobrev)

  - bug #26609 [Console] Fix check of color support on
    Windows (mlocati)

## 2.8.37 (2018-04-02)

  - bug #26727 [HttpCache] Unlink tmp file on error
    (Chansig)

  - bug #26675 [HttpKernel] DumpDataCollector: do not flush
    when a dumper is provided (ogizanagi)

  - bug #26663 [TwigBridge] Fix rendering of currency by
    MoneyType (ro0NL)

  - bug #26677 Support phpdbg SAPI in Debug::enable()
    (hkdobrev)

  - bug #26589 [Ldap] cast to string when checking empty
    passwords (ismail1432)

  - bug #26621 [Form] no type errors with invalid submitted
    data types (xabbuh)

  - bug #26337 [Finder] Fixed leading/trailing / in filename
    (lyrixx)

  - bug #26584 [TwigBridge] allow html5 compatible rendering
    of forms with null names (systemist)

  - bug #24401 [Form] Change datetime to datetime-local for
    HTML5 datetime input (pierredup)

  - bug #26370 [Security] added userChecker to
    SimpleAuthenticationProvider (i3or1s)

  - bug #26569 [BrowserKit] Fix cookie path handling when
    $domain is null (dunglas)

  - bug #26598 Fixes #26563 (open_basedir restriction in
    effect) (temperatur)

  - bug #26568 [Debug] Reset previous exception handler
    earlier to prevent infinite loop (nicolas-grekas)

  - bug #26567 [DoctrineBridge] Don't rely on
    ClassMetadataInfo->hasField in DoctrineOrmTypeGuesser
    anymore (fancyweb)

  - bug #26356 [FrameworkBundle] HttpCache is not longer
    abstract (lyrixx)

  - bug #26548 [DomCrawler] Change bad wording in
    ChoiceFormField::untick (dunglas)

  - bug #26433 [DomCrawler] extract(): fix a bug when the
    attribute list is empty (dunglas)

  - bug #26452 [Intl] Load locale aliases to support alias
    fallbacks (jakzal)

  - bug #26450 [CssSelector] Fix CSS identifiers parsing -
    they can start with dash (jakubkulhan)

## 2.8.36 (2018-03-05)

  - bug #26368 [WebProfilerBundle] Fix Debug toolbar breaks
    app (xkobal)

## 2.8.35 (2018-03-01)

  - bug #26338 [Debug] Keep previous errors of Error
    instances (Philipp91)

  - bug #26312 [Routing] Don't throw 405 when scheme
    requirement doesn't match (nicolas-grekas)

  - bug #26298 Fix ArrayInput::toString() for
    InputArgument::IS_ARRAY args (maximium)

  - bug #26236 [PropertyInfo] ReflectionExtractor: give a
    chance to other extractors if no properties (dunglas)

  - bug #25557 [WebProfilerBundle] add a way to limit ajax
    request (Simperfit)

  - bug #26228 [HttpFoundation] Fix missing 'throw' in
    JsonResponse (nicolas-grekas)

  - bug #26211 [Console] Suppress warning from
    sapi_windows_vt100_support (adawolfa)

  - bug #26156 Fixes #26136: Avoid emitting warning in
    hasParameterOption() (greg-1-anderson)

  - bug #26183 [DI] Add null check for removeChild
    (changmin.keum)

  - bug #26173 [Security] fix accessing request values
    (xabbuh)

  - bug #26159 created validator.tl.xlf for
    Form/Translations (ergiegonzaga)

  - bug #26100 [Routing] Throw 405 instead of 404 when
    redirect is not possible (nicolas-grekas)

  - bug #26040 [Process] Check PHP_BINDIR before $PATH in
    PhpExecutableFinder (nicolas-grekas)

  - bug #26012 Exit as late as possible (greg0ire)

  - bug #26111 [Security] fix merge of 2.7 into 2.8 + add
    test case (dmaicher)

  - bug #25893 [Console] Fix hasParameterOption /
    getParameterOption when used with multiple flags
    (greg-1-anderson)

  - bug #25940 [Form] keep the context when validating forms
    (xabbuh)

  - bug #25373 Use the PCRE_DOLLAR_ENDONLY modifier in route
    regexes (mpdude)

  - bug #26010 [CssSelector] For AND operator, the left
    operand should have parentheses, not only right operand
    (Arnaud CHASSEUX)

  - bug #25971 [Debug] Fix bad registration of exception
    handler, leading to mem leak (nicolas-grekas)

  - bug #25962 [Routing] Fix trailing slash redirection for
    non-safe verbs (nicolas-grekas)

  - bug #25948 [Form] Fixed empty data on expanded
    ChoiceType and FileType (HeahDude)

  - bug #25972 support sapi_windows_vt100_support for php
    7.2+ (jhdxr)

  - bug #25744 [TwigBridge] Allow label translation to be
    safe (MatTheCat)

## 2.8.34 (2018-01-29)

  - bug #25922 [HttpFoundation] Use the correct syntax for
    session gc based on Pdo driver (tanasecosminromeo)

  - bug #25933 Disable CSP header on exception pages only in
    debug (ostrolucky)

  - bug #25926 [Form] Fixed Button::setParent() when already
    submitted (HeahDude)

  - bug #25927 [Form] Fixed submitting disabled buttons
    (HeahDude)

  - bug #25891 [DependencyInjection] allow null values for
    root nodes in YAML configs (xabbuh)

  - bug #25848 [Validator] add missing parent isset and add
    test (Simperfit)

  - bug #25861 do not conflict with egulias/email-validator
    2.0+ (xabbuh)

  - bug #25851 [Validator] Conflict with
    egulias/email-validator 2.0 (emodric)

  - bug #25837 [SecurityBundle] Don't register in memory
    users as services (chalasr)

  - bug #25835 [HttpKernel] DebugHandlersListener should
    always replace the existing exception handler
    (nicolas-grekas)

  - bug #25829 [Debug] Always decorate existing exception
    handlers to deal with fatal errors (nicolas-grekas)

  - bug #25824 Fixing a bug where the dump() function
    depended on bundle ordering (weaverryan)

  - bug #25789 Enableable ArrayNodeDefinition is disabled
    for empty configuration (kejwmen)

  - bug #25816 Problem in phar see mergerequest #25579
    (betzholz)

  - bug #25781 [Form] Disallow transform dates beyond the
    year 9999 (curry684)

  - bug #25812 Copied NO language files to the new NB locale
    (derrabus)

  - bug #25801 [Router] Skip anonymous classes when loading
    annotated routes (pierredup)

  - bug #25657 [Security] Fix fatal error on non string
    username (chalasr)

  - bug #25799 Fixed Request::__toString ignoring cookies
    (Toflar)

  - bug #25755 [Debug] prevent infinite loop with faulty
    exception handlers (nicolas-grekas)

  - bug #25771 [Validator] 19 digits VISA card numbers are
    valid (xabbuh)

  - bug #25751 [FrameworkBundle] Add the missing `enabled`
    session attribute (sroze)

  - bug #25750 [HttpKernel] Turn bad hosts into 400 instead
    of 500 (nicolas-grekas)

  - bug #25490 [Serializer] Fixed throwing exception with
    option JSON_PARTIAL_OUTPUT_ON_ERROR (diversantvlz)

  - bug #25709 Tweaked some styles in the profiler tables
    (javiereguiluz)

  - feature #25669 [Security] Fail gracefully if the
    security token cannot be unserialized from the session
    (thewilkybarkid)

## 2.8.33 (2018-01-05)

  - bug #25532 [HttpKernel] Disable CSP header on exception
    pages (ostrolucky)

  - bug #25491 [Routing] Use the default host even if
    context is empty (sroze)

  - bug #25662 Dumper shouldn't use html format for phpdbg /
    cli-server (jhoff)

  - bug #25529 [Validator] Fix access to root object when
    using composite constraint (ostrolucky)

  - bug #25430 Fixes for Oracle in PdoSessionHandler
    (elislenio)

  - bug #25599 Add application/ld+json format associated to
    json (vincentchalamon)

  - bug #25407 [Console] Commands with an alias should not
    be recognized as ambiguous (Simperfit)

  - bug #25521 [Console] fix a bug when you are passing a
    default value and passing -n would output the index
    (Simperfit)

  - bug #25489 [FrameworkBundle] remove esi/ssi renderers if
    inactive (dmaicher)

  - bug #25427 Preserve percent-encoding in URLs when
    performing redirects in the UrlMatcher (mpdude)

  - bug #25480 [FrameworkBundle] add missing validation
    options to XSD file (xabbuh)

  - bug #25487 [Console] Fix a bug when passing a letter
    that could be an alias (Simperfit)

  - bug #25233 [TwigBridge][Form] Fix hidden currency
    element with Bootstrap 3 theme (julienfalque)

  - bug #25408 [Debug] Fix catching fatal errors in case of
    nested error handlers (nicolas-grekas)

  - bug #25330 [HttpFoundation] Support 0 bit netmask in
    IPv6 (`::/0`) (stephank)

  - bug #25410 [HttpKernel] Fix logging of post-terminate
    errors/exceptions (nicolas-grekas)

  - bug #25323 [ExpressionLanguage] throw an SyntaxError
    instead of an undefined index notice (Simperfit)

## 2.8.32 (2017-12-04)

  - bug #25278 Fix for missing whitespace control modifier
    in form layout (kubawerlos)

  - bug #25236 [Form][TwigBridge] Fix collision between view
    properties and form fields (yceruto)

  - bug #25258 [link] Prevent warnings when running link
    with 2.7 (dunglas)

  - bug #24750 [Validator] ExpressionValidator should use
    OBJECT_TO_STRING (Simperfit)

  - bug #25182 [HttpFoundation] AutExpireFlashBag should not
    clear new flashes (Simperfit, sroze)

  - bug #25152 [Form] Don't rely on
    `Symfony\Component\HttpFoundation\File\File` if
    http-foundation isn't in FileType (issei-m)

  - bug #24987 [Console] Fix global console flag when used
    in chain (Simperfit)

  - bug #25043 [Yaml] added ability for substitute aliases
    when mapping is on single line (Micha&#x142; Strzelecki,
    xabbuh)

  - bug #25102 [Form] Fixed ContextErrorException in
    FileType (chihiro-adachi)

  - bug #25130 [DI] Fix handling of inlined definitions by
    ContainerBuilder (nicolas-grekas)

  - bug #25072 [Bridge/PhpUnit] Remove trailing ' ' from
    ClockMock::microtime(false) (joky)

  - bug #24956 Fix ambiguous pattern (weltling)

## 2.8.31 (2017-11-16)

  - security #24995 Validate redirect targets using the
    session cookie domain (nicolas-grekas)

  - security #24994 Prevent bundle readers from breaking out
    of paths (xabbuh)

  - security #24993 Ensure that submitted data are uploaded
    files (xabbuh)

  - security #24992 Namespace generated CSRF tokens
    depending of the current scheme (dunglas)

## 2.8.30 (2017-11-13)

  - bug #24952 [HttpFoundation] Fix session-related BC break
    (nicolas-grekas, sroze)

  - bug #24929 [Console] Fix traversable autocomplete values
    (ro0NL)

## 2.8.29 (2017-11-10)

  - bug #24888 [FrameworkBundle] Specifically inject the
    debug dispatcher in the collector (ogizanagi)

  - bug #24909 [Intl] Update ICU data to 60.1 (jakzal)

  - bug #24906 [Bridge/ProxyManager] Remove direct reference
    to value holder property (nicolas-grekas)

  - bug #24900 [Validator] Fix Costa Rica IBAN format
    (Bozhidar Hristov)

  - bug #24904 [Validator] Add Belarus IBAN format (Bozhidar
    Hristov)

  - bug #24531 [HttpFoundation] Fix forward-compat of
    NativeSessionStorage with PHP 7.2 (sroze)

  - bug #24665 Fix dump panel hidden when closing a dump
    (julienfalque)

  - bug #24814 [Intl] Make intl-data tests pass and save
    language aliases again (jakzal)

  - bug #24764 [HttpFoundation] add Early Hints to Reponse
    to fix test (Simperfit)

  - bug #24605 [FrameworkBundle] Do not load
    property_access.xml if the component isn't installed
    (ogizanagi)

  - bug #24606 [HttpFoundation] Fix FileBag issue with
    associative arrays (enumag)

  - bug #24660 Escape trailing \ in QuestionHelper
    autocompletion (kamazee)

  - bug #24644 [Security] Fixed auth provider authenticate()
    cannot return void (glye)

  - bug #24642 [Routing] Fix resource miss (dunglas)

  - bug #24608 Adding the Form default theme files to be
    warmed up in Twig's cache (weaverryan)

  - bug #24626 streamed response should return $this (DQNEO)

  - bug #24589 Username and password in basic auth are
    allowed to contain '.' (Richard Quadling)

  - bug #24566 Fixed unsetting from loosely equal keys
    OrderedHashMap (maryo)

  - bug #24570 [Debug] Fix same vendor detection in class
    loader (Jean-Beru)

  - bug #24563 [Serializer] ObjectNormalizer: throw if
    PropertyAccess isn't installed (dunglas)

  - bug #24571 [PropertyInfo] Add support for the iterable
    type (dunglas)

  - bug #24579 pdo session fix (mxp100)

  - bug #24536 [Security] Reject remember-me token if
    UserCheckerInterface::checkPostAuth() fails (kbond)

  - bug #24519 [Validator] [Twig] added magic method
    __isset() to File Constraint class (loru88)

  - bug #24532 [DI] Fix possible incorrect php-code when
    dumped strings contains newlines (Strate)

  - bug #24502 [HttpFoundation] never match invalid IP
    addresses (xabbuh)

  - bug #24460 [Form] fix parsing invalid floating point
    numbers (xabbuh)

  - bug #24490 [HttpFoundation] Combine Cache-Control
    headers (c960657)

  - bug #23711 Fix support for PHP 7.2 (Simperfit,
    nicolas-grekas)

  - bug #24494 [HttpFoundation] Add missing
    session.lazy_write config option (nicolas-grekas)

  - bug #24434 [Form] Use for=ID on radio/checkbox label.
    (Nyholm)

  - bug #24455 [Console] Escape command usage (sroze)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-2bdfc9dc67"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"php-symfony-2.8.42-1.fc27")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony");
}
