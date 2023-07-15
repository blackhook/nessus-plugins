#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-ba0b683c10.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120738);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-11385", "CVE-2018-11386", "CVE-2018-11406", "CVE-2018-11408");
  script_xref(name:"FEDORA", value:"2018-ba0b683c10");

  script_name(english:"Fedora 28 : php-symfony3 (2018-ba0b683c10)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 3.4.11** (2018-05-25)

  - bug #27364 [DI] Fix bad exception on uninitialized
    references to non-shared services (nicolas-grekas)

  - bug #27359 [HttpFoundation] Fix perf issue during
    MimeTypeGuesser intialization (nicolas-grekas)

  - security #cve-2018-11408 [SecurityBundle] Fail if
    security.http_utils cannot be configured

  - security #cve-2018-11406 clear CSRF tokens when the user
    is logged out

  - security #cve-2018-11385 migrating session for
    UsernamePasswordJsonAuthenticationListener

  - security #cve-2018-11385 Adding session authentication
    strategy to Guard to avoid session fixation

  - security #cve-2018-11385 Adding session strategy to ALL
    listeners to avoid *any* possible fixation

  - security #cve-2018-11386 [HttpFoundation] Break infinite
    loop in PdoSessionHandler when MySQL is in loose mode

  - bug #27341 [WebProfilerBundle] Fixed validator/dump
    trace CSS (yceruto)

  - bug #27337 [FrameworkBundle] fix typo in
    CacheClearCommand (emilielorenzo)

----

**Version 3.4.10** (2018-05-21)

  - bug #27264 [Validator] Use strict type in URL validator
    (mimol91)

  - bug #27267 [DependencyInjection] resolve array env vars
    (jamesthomasonjr)

  - bug #26781 [Form] Fix precision of
    MoneyToLocalizedStringTransformer's divisions on
    transform() (syastrebov)

  - bug #27286 [Translation] Add Occitan plural rule
    (kylekatarnls)

  - bug #27271 [DI] Allow defining bindings on
    ChildDefinition (nicolas-grekas)

  - bug #27246 Disallow invalid characters in session.name
    (ostrolucky)

  - bug #27287 [PropertyInfo] fix resolving parent|self type
    hints (nicolas-grekas)

  - bug #27281 [HttpKernel] Fix dealing with self/parent in
    ArgumentMetadataFactory (fabpot)

  - bug #24805 [Security] Fix logout (MatTheCat)

  - bug #27265 [DI] Shared services should not be inlined in
    non-shared ones (nicolas-grekas)

  - bug #27141 [Process] Suppress warnings when open_basedir
    is non-empty (cbj4074)

  - bug #27250 [Session] limiting :key for GET_LOCK to 64
    chars (oleg-andreyev)

  - bug #27237 [Debug] Fix populating error_get_last() for
    handled silent errors (nicolas-grekas)

  - bug #27232 [Cache][Lock] Fix usages of error_get_last()
    (nicolas-grekas)

  - bug #27236 [Filesystem] Fix usages of error_get_last()
    (nicolas-grekas)

  - bug #27191 [DI] Display previous error messages when
    throwing unused bindings (nicolas-grekas)

  - bug #27231 [FrameworkBundle] Fix cache:clear on vagrant
    (nicolas-grekas)

  - bug #27222 [WebProfilerBundle][Cache] Fix misses
    calculation when calling getItems (fsevestre)

  - bug #27227 [HttpKernel] Handle NoConfigurationException
    'onKernelException()' (nicolas-grekas)

  - bug #27152 [HttpFoundation] use brace-style regex
    delimiters (xabbuh)

  - bug #27158 [Cache] fix logic for fetching tag versions
    on TagAwareAdapter (dmaicher)

  - bug #27143 [Console] By default hide the short exception
    trace line from exception messages in Symfony's commands
    (yceruto)

  - bug #27133 [Doctrine Bridge] fix priority for doctrine
    event listeners (dmaicher)

  - bug #27135 [FrameworkBundle] Use the correct service id
    for CachePoolPruneCommand in its compiler pass
    (DemonTPx)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-ba0b683c10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony3 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/05");
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
if (rpm_check(release:"FC28", reference:"php-symfony3-3.4.11-1.fc28")) flag++;


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
