#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-b85d51cc47.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101709);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2017-b85d51cc47");

  script_name(english:"Fedora 26 : php-pear-PHP-CodeSniffer (2017-b85d51cc47)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 3.0.1**

  - This release contains a fix for a **security advisory**
    related to the improper handling of a shell command

  - A properly crafted filename would allow for arbitrary
    code execution when using the --filter=gitmodified
    command line option

  - All version 3 users are encouraged to upgrade to this
    version, especially if you are checking 3rd-party code

  - e.g., you run PHPCS over libraries that you did not
    write

  - e.g., you provide a web service that runs PHPCS over
    user-uploaded files or 3rd-party repositories

  - e.g., you allow external tool paths to be set by
    user-defined values

  - If you are unable to upgrade but you check 3rd-party
    code, ensure you are not using the Git modified filter

  - This advisory does not affect PHP_CodeSniffer version 2.

  - Thanks to Sergei Morozov for the report and patch

  - Arguments on the command line now override or merge with
    those specified in a ruleset.xml file in all cases

  - PHPCS now stops looking for a phpcs.xml file as soon as
    one is found, favoring the closest one to the current
    dir

  - Added missing help text for the --stdin-path CLI option
    to --help

  - Re-added missing help text for the --file-list and
    --bootstrap CLI options to --help

  - Runner::runPHPCS() and Runner::runPHPCBF() now return an
    exit code instead of exiting directly (request #1484)

  - The Squiz standard now enforces short array syntax by
    default

  - The autoloader is now working correctly with classes
    created with class_alias()

  - The autoloader will now search for files inside all
    directories in the installed_paths config var

  - This allows autoloading of files inside included custom
    coding standards without manually requiring them

  - You can now specify a namespace for a custom coding
    standard, used by the autoloader to load non-sniff
    helper files

  - Also used by the autoloader to help other standards
    directly include sniffs for your standard

  - Set the value to the namespace prefix you are using for
    sniff files (everything up to \Sniffs\)

  - e.g., if your namespace format is
    MyProject\CS\Standard\Sniffs\Category set the namespace
    to MyProject\CS\Standard

  - If ommitted, the namespace is assumed to be the same as
    the directory name containing the ruleset.xml file

  - The namespace is set in the ruleset tag of the
    ruleset.xml file

  - e.g., ruleset name='My Coding Standard'
    namespace='MyProject\CS\Standard'

  - Rulesets can now specify custom autoloaders using the
    new autoload tag

  - Autloaders are included while the ruleset is being
    processed and before any custom sniffs are included

  - Allows for very custom autoloading of helper classes
    well before the boostrap files are included

  - The PEAR standard now includes
    Squiz.Commenting.DocCommentAlignment

  - It previously broke comments onto multiple lines, but
    didn't align them

  - Fixed a problem where excluding a message from a custom
    standard's own sniff would exclude the whole sniff

  - This caused some PSR2 errors to be under-reported

  - Fixed bug #1442 : T_NULLABLE detection not working for
    nullable parameters and return type hints in some cases

  - Fixed bug #1447 : Running the unit tests with a phpunit
    config file breaks the test suite

  - Unknown arguments were not being handled correctly, but
    are now stored in $config->unknown

  - Fixed bug #1449 : Generic.Classes.OpeningBraceSameLine
    doesn't detect comment before opening brace

  - Thanks to Juliette Reinders Folmer for the patch

  - Fixed bug #1450 : Coding standard located under an
    installed_path with the same directory name throws an
    error

  - Thanks to Juliette Reinders Folmer for the patch

  - Fixed bug #1451 : Sniff exclusions/restrictions dont
    work with custom sniffs unless they use the
    PHP_CodeSniffer NS

  - Fixed bug #1454 : Squiz.WhiteSpace.OperatorSpacing is
    not checking spacing on either side of a short ternary
    operator

  - Thanks to Mponos George for the patch

  - Fixed bug #1495 : Setting an invalid installed path
    breaks all commands

  - Fixed bug #1496 : Squiz.Strings.DoubleQuoteUsage not
    unescaping dollar sign when fixing

  - Thanks to Micha? Bundyra for the patch

  - Fixed bug #1501 : Interactive mode is broken

  - Fixed bug #1504 : PSR2.Namespaces.UseDeclaration hangs
    fixing use statement with no trailing code

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-b85d51cc47"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pear-PHP-CodeSniffer package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear-PHP-CodeSniffer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:26");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/17");
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
if (! preg(pattern:"^26([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 26", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC26", reference:"php-pear-PHP-CodeSniffer-3.0.1-1.fc26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pear-PHP-CodeSniffer");
}
