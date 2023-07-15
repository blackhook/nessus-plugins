#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-7f43cbdb69.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111712);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-14773");
  script_xref(name:"FEDORA", value:"2018-7f43cbdb69");

  script_name(english:"Fedora 27 : php-symfony4 (2018-7f43cbdb69)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 4.0.14 (2018-08-01)

  - security #cve-2018-14774 [HttpKernel] fix trusted
    headers management in HttpCache and
    InlineFragmentRenderer (nicolas-grekas)

  - security #cve-2018-14773 [HttpFoundation] Remove support
    for legacy and risky HTTP headers (nicolas-grekas)

  - bug #28003 [HttpKernel] Fixes invalid REMOTE_ADDR in
    inline subrequest when configuring trusted proxy with
    subnet (netiul)

  - bug #28007 [FrameworkBundle] fixed guard event names for
    transitions (destillat)

  - bug #28045 [HttpFoundation] Fix Cookie::isCleared
    (ro0NL)

  - bug #28080 [HttpFoundation] fixed using _method
    parameter with invalid type (Phobetor)

  - bug #28052 [HttpKernel] Fix merging bindings for
    controllers' locators (nicolas-grekas)

## 4.0.13 (2018-07-23)

  - bug #28005 [HttpKernel] Fixed templateExists on parse
    error of the template name (yceruto)

  - bug #27997 Serbo-Croatian has Serbian plural rule
    (kylekatarnls)

  - bug #26193 Fix false-positive deprecation notices for
    TranslationLoader and WriteCheckSessionHandler (iquito)

  - bug #27941 [WebProfilerBundle] Fixed icon alignment
    issue using Bootstrap 4.1.2 (jmsche)

  - bug #27937 [HttpFoundation] reset callback on
    StreamedResponse when setNotModified() is called
    (rubencm)

  - bug #27927 [HttpFoundation] Suppress side effects in
    'get' and 'has' methods of NamespacedAttributeBag
    (webnet-fr)

  - bug #27923 [Form/Profiler] Massively reducing memory
    footprint of form profiling pages... (VincentChalnot)

  - bug #27918 [Console] correctly return parameter's
    default value on '--' (seschwar)

  - bug #27904 [Filesystem] fix lock file permissions
    (fritzmg)

  - bug #27903 [Lock] fix lock file permissions (fritzmg)

  - bug #27889 [Form] Replace .initialism with
    .text-uppercase. (vudaltsov)

  - bug #27902 Fix the detection of the Process new argument
    (stof)

  - bug #27885 [HttpFoundation] don't encode cookie name for
    BC (nicolas-grekas)

  - bug #27782 [DI] Fix dumping ignore-on-uninitialized
    references to synthetic services (nicolas-grekas)

  - bug #27435 [OptionResolver] resolve arrays (Doctrs)

  - bug #27728 [TwigBridge] Fix missing path and separators
    in loader paths list on debug:twig output (yceruto)

  - bug #27837 [PropertyInfo] Fix dock block lookup fallback
    loop (DerManoMann)

  - bug #27758 [WebProfilerBundle] Prevent toolbar links
    color override by css (alcalyn)

  - bug #27847 [Security] Fix accepting null as $uidKey in
    LdapUserProvider (louhde)

  - bug #27834 [DI] Don't show internal service id on
    binding errors (nicolas-grekas)

  - bug #27831 Check for Hyper terminal on all operating
    systems. (azjezz)

  - bug #27794 Add color support for Hyper terminal .
    (azjezz)

  - bug #27809 [HttpFoundation] Fix tests: new message for
    status 425 (dunglas)

  - bug #27618 [PropertyInfo] added handling of nullable
    types in PhpDoc (oxan)

  - bug #27659 [HttpKernel] Make AbstractTestSessionListener
    compatible with CookieClearingLogoutHandler
    (thewilkybarkid)

  - bug #27752 [Cache] provider does not respect option
    maxIdLength with versioning enabled (Constantine
    Shtompel)

  - bug #27776 [ProxyManagerBridge] Fix support of private
    services (bis) (nicolas-grekas)

  - bug #27714 [HttpFoundation] fix session tracking counter
    (nicolas-grekas, dmaicher)

  - bug #27747 [HttpFoundation] fix registration of session
    proxies (nicolas-grekas)

  - bug #27722 Redesign the Debug error page in prod
    (javiereguiluz)

  - bug #27716 [DI] fix dumping deprecated service in yaml
    (nicolas-grekas)

## 4.0.12 (2018-06-25)

  - bug #27626 [TwigBundle][DX] Only add the Twig
    WebLinkExtension if the WebLink component is enabled
    (thewilkybarkid)

  - bug #27701 [SecurityBundle] Dont throw if
    'security.http_utils' is not found (nicolas-grekas)

  - bug #27690 [DI] Resolve env placeholder in logs (ro0NL)

  - bug #26534 allow_extra_attributes does not throw an
    exception as documented (deviantintegral)

  - bug #27668 [Lock] use 'r+' for fopen (fixes issue on
    Solaris) (fritzmg)

  - bug #27669 [Filesystem] fix file lock on SunOS (fritzmg)

  - bug #27662 [HttpKernel] fix handling of nested Error
    instances (xabbuh)

  - bug #26845 [Config] Fixing GlobResource when inside phar
    archive (vworldat)

  - bug #27382 [Form] Fix error when rendering a
    DateIntervalType form with exactly 0 weeks (krixon)

  - bug #27309 Fix surrogate not using original request
    (Toflar)

  - bug #27467 [HttpKernel] fix session tracking in
    surrogate master requests (nicolas-grekas)

  - bug #27630 [Validator][Form] Remove BOM in some xlf
    files (gautierderuette)

  - bug #27596 [Framework][Workflow] Added support for
    interfaces (vudaltsov)

  - bug #27593 [ProxyManagerBridge] Fixed support of private
    services (nicolas-grekas)

  - bug #27591 [VarDumper] Fix dumping ArrayObject and
    ArrayIterator instances (nicolas-grekas)

  - bug #27581 Fix bad method call with guard authentication
    + session migration (weaverryan)

  - bug #27576 [Cache] Fix expiry comparisons in array-based
    pools (nicolas-grekas)

  - bug #27556 Avoiding session migration for stateless
    firewall UsernamePasswordJsonAuthenticationListener
    (weaverryan)

  - bug #27452 Avoid migration on stateless firewalls
    (weaverryan)

  - bug #27568 [DI] Deduplicate generated proxy classes
    (nicolas-grekas)

  - bug #27326 [Serializer] deserialize from xml: Fix a
    collection that contains the only one element
    (webnet-fr)

  - bug #27567 [PhpUnitBridge] Fix error on some Windows OS
    (Nsbx)

  - bug #27357 [Lock] Remove released semaphore (jderusse)

  - bug #27416 TagAwareAdapter over non-binary memcached
    connections corrupts memcache (Aleksey Prilipko)

  - bug #27514 [Debug] Pass previous exception to
    FatalErrorException (pmontoya)

  - bug #27516 Revert 'bug #26138 [HttpKernel] Catch
    HttpExceptions when templating is not installed
    (cilefen)' (nicolas-grekas)

  - bug #27318 [Cache] memcache connect should not add
    duplicate entries on sequential calls (Aleksey Prilipko)

  - bug #27389 [Serializer] Fix serializer tries to
    denormalize null values on nullable properties
    (ogizanagi)

  - bug #27272 [FrameworkBundle] Change priority of
    AddConsoleCommandPass to TYPE_BEFORE_REMOVING (upyx)

  - bug #27396 [HttpKernel] fix registering IDE links
    (nicolas-grekas)

  - bug #26973 [HttpKernel] Set first trusted proxy as
    REMOTE_ADDR in InlineFragmentRenderer. (kmadejski)

  - bug #27303 [Process] Consider 'executable' suffixes
    first on Windows (sanmai)

  - bug #27297 Triggering RememberMe's loginFail() when
    token cannot be created (weaverryan)

  - bug #27344 [HttpKernel] reset kernel start time on
    reboot (kiler129)

  - bug #27365 [Serializer] Check the value of
    enable_max_depth if defined (dunglas)

  - bug #27358 [PhpUnitBridge] silence some stderr outputs
    (ostrolucky)

  - bug #27366 [DI] never inline lazy services
    (nicolas-grekas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-7f43cbdb69"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony4 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");
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
if (rpm_check(release:"FC27", reference:"php-symfony4-4.0.14-1.fc27")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony4");
}
