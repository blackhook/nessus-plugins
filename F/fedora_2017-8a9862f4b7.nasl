#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-8a9862f4b7.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105926);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2017-8a9862f4b7");

  script_name(english:"Fedora 27 : php-symfony4 (2017-8a9862f4b7)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 4.0.1 (2017-12-05)

  - bug #25304 [Bridge/PhpUnit] Prefer $_SERVER['argv'] over
    $argv (ricknox)

  - bug #25272 [SecurityBundle] fix setLogoutOnUserChange
    calls for context listeners (dmaicher)

  - bug #25282 [DI] Register singly-implemented interfaces
    when doing PSR-4 discovery (nicolas-grekas)

  - bug #25274 [Security] Adding a GuardAuthenticatorHandler
    alias (weaverryan)

  - bug #25308 [FrameworkBundle] Fix a bug where a color tag
    will be shown when passing an antislash (Simperfit)

  - bug #25278 Fix for missing whitespace control modifier
    in form layout (kubawerlos)

  - bug #25306 [Form][TwigBridge] Fix collision between view
    properties and form fields (yceruto)

  - bug #25305 [Form][TwigBridge] Fix collision between view
    properties and form fields (yceruto)

  - bug #25236 [Form][TwigBridge] Fix collision between view
    properties and form fields (yceruto)

  - bug #25312 [DI] Fix deep-inlining of non-shared refs
    (nicolas-grekas)

  - bug #25309 [Yaml] parse newlines in quoted multiline
    strings (xabbuh)

  - bug #25313 [DI] Fix missing unset leading to
    false-positive circular ref (nicolas-grekas)

  - bug #25268 [DI] turn $private to protected in dumped
    container, to make cache:clear BC (nicolas-grekas)

  - bug #25285 [DI] Throw an exception if Expression
    Language is not installed (sroze)

  - bug #25241 [Yaml] do not eagerly filter comment lines
    (xabbuh)

  - bug #25284 [DI] Cast ids to string, as done on 3.4
    (nicolas-grekas, sroze)

  - bug #25297 [Validator] Fixed the
    @Valid(groups={'group'}) against null exception case
    (vudaltsov)

  - bug #25255 [Console][DI] Fail gracefully
    (nicolas-grekas)

  - bug #25264 [DI] Trigger deprecation when setting a
    to-be-private synthetic service (nicolas-grekas)

  - bug #25258 [link] Prevent warnings when running link
    with 2.7 (dunglas)

  - bug #25244 [DI] Add missing deprecation when fetching
    private services from ContainerBuilder (nicolas-grekas)

  - bug #24750 [Validator] ExpressionValidator should use
    OBJECT_TO_STRING (Simperfit)

  - bug #25247 [DI] Fix false-positive circular exception
    (nicolas-grekas)

  - bug #25226 [HttpKernel] Fix issue when resetting
    DumpDataCollector (Pierstoval)

  - bug #25230 Use a more specific file for detecting the
    bridge (greg0ire)

  - bug #25232 [WebProfilerBundle] [TwigBundle] Fix Profiler
    breaking XHTML pages (tistre)

## 4.0.0 (2017-11-30)

  - bug #25220 [HttpFoundation] Add Session::isEmpty(), fix
    MockFileSessionStorage to behave like the native one
    (nicolas-grekas)

  - bug #25209 [VarDumper] Dont use empty(), it chokes on eg
    GMP objects (nicolas-grekas)

  - bug #25200 [HttpKernel] Arrays with scalar values passed
    to ESI fragment renderer throw deprecation notice
    (Simperfit)

  - bug #25201 [HttpKernel] Add a better error messages when
    passing a private or non-tagged controller (Simperfit)

  - bug #25155 [DependencyInjection] Detect case mismatch in
    autowiring (Simperfit, sroze)

  - bug #25217 [Dotenv] Changed preg_match flags from null
    to 0 (deekthesqueak)

  - bug #25180 [DI] Fix circular reference when using
    setters (nicolas-grekas)

  - bug #25204 [DI] Clear service reference graph
    (nicolas-grekas)

  - bug #25203 [DI] Fix infinite loop in
    InlineServiceDefinitionsPass (nicolas-grekas)

  - bug #25185 [Serializer] Do not cache attributes if
    `attributes` in context (sroze)

  - bug #25190 [HttpKernel] Keep legacy container files for
    concurrent requests (nicolas-grekas)

  - bug #25182 [HttpFoundation] AutExpireFlashBag should not
    clear new flashes (Simperfit, sroze)

  - bug #25174 [Translation] modify definitions only if the
    do exist (xabbuh)

  - bug #25179 [FrameworkBundle][Serializer] Remove
    YamlEncoder definition if Yaml component isn't installed
    (ogizanagi)

  - bug #25160 [DI] Prevent a ReflectionException during
    cache:clear when the parent class doesn't exist
    (dunglas)

  - bug #25163 [DI] Fix tracking of env vars in exceptions
    (nicolas-grekas)

  - bug #25162 [HttpKernel] Read $_ENV when checking
    SHELL_VERBOSITY (nicolas-grekas)

  - bug #25158 [DI] Remove unreachable code (GawainLynch)

  - bug #25152 [Form] Don't rely on
    `Symfony\Component\HttpFoundation\File\File` if
    http-foundation isn't in FileType (issei-m)

  - bug #24987 [Console] Fix global console flag when used
    in chain (Simperfit)

  - bug #25137 Adding checks for the expression language
    (weaverryan)

  - bug #25151 [FrameworkBundle] Automatically enable the
    CSRF protection if CSRF manager exists (sroze)

  - bug #25043 [Yaml] added ability for substitute aliases
    when mapping is on single line (Micha&#x142; Strzelecki,
    xabbuh)

## 4.0.0-RC2 (2017-11-24)

  - bug #25146 [DI] Dont resolve envs in service ids
    (nicolas-grekas)

  - bug #25113 [Routing] Fix 'config-file-relative'
    annotation loader resources (nicolas-grekas, sroze)

  - bug #25065 [FrameworkBundle] Update translation commands
    to work with default paths (yceruto)

  - bug #25109 Make debug:container search command
    case-insensitive (jzawadzki)

  - bug #25121 [FrameworkBundle] Fix AssetsInstallCommand
    (nicolas-grekas)

  - bug #25102 [Form] Fixed ContextErrorException in
    FileType (chihiro-adachi)

  - bug #25130 [DI] Fix handling of inlined definitions by
    ContainerBuilder (nicolas-grekas)

  - bug #25119 [DI] Fix infinite loop when analyzing
    references (nicolas-grekas)

  - bug #25094 [FrameworkBundle][DX] Display a nice error
    message if an enabled component is missing (derrabus)

  - bug #25100 [SecurityBundle] providerIds is undefined
    error when firewall provider is not specified (karser)

  - bug #25100 [SecurityBundle] providerIds is undefined
    error when firewall provider is not specified (karser)

  - bug #25100 [SecurityBundle] providerIds is undefined
    error when firewall provider is not specified (karser)

  - bug #25097 [Bridge\PhpUnit] Turn 'preserveGlobalState'
    to false by default, revert 'Blacklist' removal
    (nicolas-grekas)

## 4.0.0-RC1 (2017-11-21)

  - bug #25077 [Bridge/Twig] Let getFlashes starts the
    session (MatTheCat)

  - bug #25082 [HttpKernel] Disable container inlining when
    legacy inlining has been used (nicolas-grekas)

  - bug #25022 [Filesystem] Updated
    Filesystem::makePathRelative (inso)

  - bug #25072 [Bridge/PhpUnit] Remove trailing ' ' from
    ClockMock::microtime(false) (joky)

  - bug #25069 [Debug] Fix undefined variable $lightTrace
    (nicolas-grekas)

  - bug #25053 [Serializer] Fixing PropertyNormalizer
    supports parent properties (Christopher Hertel)

  - bug #25055 [DI] Analyze setter-circular deps more
    precisely (nicolas-grekas)

  - feature #25056 [Bridge/PhpUnit] Sync the bridge version
    installed in vendor/ and in phpunit clone
    (nicolas-grekas)

  - bug #25048 Allow EnumNode name to be null (MatTheCat)

  - bug #25045 [SecurityBundle] Don't trigger auto-picking
    notice if provider is set per listener (chalasr)

  - bug #25033 [FrameworkBundle] Dont create empty bundles
    directory by default (ro0NL)

  - bug #25037 [DI] Skip hot_path tag for deprecated
    services as their class might also be (nicolas-grekas)

  - bug #25038 [Cache] Memcached options should ignore
    'lazy' (nicolas-grekas)

  - bug #25014 Move deprecation under use statements
    (greg0ire)

  - bug #25030 [Console] Fix ability to disable lazy
    commands (chalasr)

  - bug #25032 [Bridge\PhpUnit] Disable broken auto-require
    mechanism of phpunit (nicolas-grekas)

  - bug #25016 [HttpKernel] add type-hint for the
    requestType (Simperfit)

  - bug #25027 [FrameworkBundle] Hide server:log command
    based on deps (sroze)

  - bug #24991 [DependencyInjection] Single typed argument
    can be applied on multiple parameters (nicolas-grekas,
    sroze)

  - bug #24983 [Validator] enter the context in which to
    validate (xabbuh)

  - bug #24956 Fix ambiguous pattern (weltling)

  - bug #24732 [DependencyInjection] Prevent service:method
    factory notation in PHP config (vudaltsov)

  - bug #24979 [HttpKernel] remove services resetter even
    when it's an alias (xabbuh)

  - bug #24972 [HttpKernel] Fix service arg resolver for
    controllers as array callables (sroze, nicolas-grekas)

  - bug #24971 [FrameworkBundle] Empty event dispatcher
    earlier in CacheClearCommand (nicolas-grekas)

  - security #24995 Validate redirect targets using the
    session cookie domain (nicolas-grekas)

  - security #24994 Prevent bundle readers from breaking out
    of paths (xabbuh)

  - security #24993 Ensure that submitted data are uploaded
    files (xabbuh)

  - security #24992 Namespace generated CSRF tokens
    depending of the current scheme (dunglas)

  - bug #24975 [DomCrawler] Type fix Crawler::
    discoverNamespace() (VolCh)

  - bug #24954 [DI] Fix dumping with custom base class
    (nicolas-grekas)

  - bug #24952 [HttpFoundation] Fix session-related BC break
    (nicolas-grekas, sroze)

  - bug #24943 [FrameworkBundle] Wire the translation.reader
    service instead of deprecated translation.loader in
    commands (ogizanagi)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-8a9862f4b7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony4 package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/15");
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
if (rpm_check(release:"FC27", reference:"php-symfony4-4.0.1-1.fc27")) flag++;


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
