#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-9c38d1dc1d.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120653);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-14773");
  script_xref(name:"FEDORA", value:"2018-9c38d1dc1d");

  script_name(english:"Fedora 28 : php-symfony3 (2018-9c38d1dc1d)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 3.4.14 (2018-08-01)

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

## 3.4.13 (2018-07-23)

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

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-9c38d1dc1d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony3 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"php-symfony3-3.4.14-1.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony3");
}
