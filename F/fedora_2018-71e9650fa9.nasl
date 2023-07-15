#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-71e9650fa9.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120525);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-71e9650fa9");

  script_name(english:"Fedora 28 : php-zendframework-zend-http (2018-71e9650fa9)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 2.8.1 - 2018-08-01

### Added

  - Nothing.

### Changed

  - This release modifies how
    `Zend\Http\PhpEnvironment\Request` marshals the request
    URI. In prior releases, we would attempt to inspect the
    `X-Rewrite-Url` and `X-Original-Url` headers, using
    their values, if present. These headers are issued by
    the ISAPI_Rewrite module for IIS (developed by
    HeliconTech). However, we have no way of guaranteeing
    that the module is what issued the headers, making it an
    unreliable source for discovering the URI. As such, we
    have removed this feature in this release of zend-http.

    If you are developing a zend-mvc application, you can
    mimic the functionality by adding a bootstrap listener
    like the following :

``` public function onBootstrap(MvcEvent $mvcEvent) { $request =
$mvcEvent->getRequest(); $requestUri = null;

$httpXRewriteUrl = $request->getHeader('X-Rewrite-Url'); if
($httpXRewriteUrl) { $requestUri = $httpXRewriteUrl->getFieldValue();
}

$httpXOriginalUrl = $request->getHeader('X-Original-Url');
if ($httpXOriginalUrl) { $requestUri =
$httpXOriginalUrl->getFieldValue(); }

if ($requestUri) { $request->setUri($requestUri) } } ```

If you use a listener such as the above, make sure you also
instruct your web server to strip any incoming headers of
the same name so that you can guarantee they are issued by
the ISAPI_Rewrite module.

### Deprecated

  - Nothing.

### Removed

  - Nothing.

### Fixed

  - Nothing.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-71e9650fa9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-zendframework-zend-http package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-zendframework-zend-http");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:28");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
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
if (rpm_check(release:"FC28", reference:"php-zendframework-zend-http-2.8.1-1.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-zendframework-zend-http");
}
