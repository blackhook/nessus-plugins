#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-e86155be6e.
#

include("compat.inc");

if (description)
{
  script_id(123051);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/23 11:21:12");

  script_xref(name:"FEDORA", value:"2019-e86155be6e");

  script_name(english:"Fedora 28 : php-twig2 (2019-e86155be6e)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 2.7.2** (2019-03-12)

  - added TemplateWrapper::getTemplateName()

----

**Version 2.7.1** (2019-03-12)

  - fixed class aliases

----

**Version 2.7.0** (2019-03-12)

  - fixed sandbox security issue (under some circumstances,
    calling the __toString() method on an object was
    possible even if not allowed by the security policy)

  - fixed batch filter clobbers array keys when fill
    parameter is used

  - added preserveKeys support for the batch filter

  - fixed 'embed' support when used from
    'template_from_string'

  - deprecated passing a Twig\Template to
    Twig\Environment::load()/Twig\Environment::resolveTempla
    te()

  - added the possibility to pass a TemplateWrapper to
    Twig\Environment::load()

  - marked Twig\Environment::getTemplateClass() as internal
    (implementation detail)

  - improved the performance of the sandbox

  - deprecated the spaceless tag

  - added a spaceless filter

  - added max value to the 'random' function

  - deprecated Twig\Extension\InitRuntimeInterface

  - deprecated Twig\Loader\ExistsLoaderInterface

  - deprecated PSR-0 classes in favor of namespaced ones

  - made namespace classes the default classes (PSR-0 ones
    are aliases now)

  - added Twig\Loader\ChainLoader::getLoaders()

  - removed duplicated directory separator in
    FilesystemLoader

  - deprecated the 'base_template_class' option on
    Twig\Environment

  - deprecated the Twig\Environment::getBaseTemplateClass()
    and Twig\Environment::setBaseTemplateClass() methods

  - changed internal code to use the namespaced classes as
    much as possible

  - deprecated Twig_Parser::isReservedMacroName()

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-e86155be6e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-twig2 package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-twig2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/25");
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
if (! preg(pattern:"^28([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 28", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC28", reference:"php-twig2-2.7.2-1.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-twig2");
}
