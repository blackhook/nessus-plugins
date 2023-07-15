#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-7da5983771.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120563);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2018-7da5983771");

  script_name(english:"Fedora 28 : php-zendframework-zend-feed (2018-7da5983771)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 2.10.3 - 2018-08-01

### Added

  - Nothing.

### Changed

  - This release modifies how
    `Zend\Feed\Pubsubhubbub\AbstractCallback::_detectCallbac
    kUrl()` marshals the request URI. In prior releases, we
    would attempt to inspect the `X-Rewrite-Url` and
    `X-Original-Url` headers, using their values, if
    present. These headers are issued by the ISAPI_Rewrite
    module for IIS (developed by HeliconTech). However, we
    have no way of guaranteeing that the module is what
    issued the headers, making it an unreliable source for
    discovering the URI. As such, we have removed this
    feature in this release.

    The method is not called internally. If you are calling
    the method from your own extension and need support for
    ISAPI_Rewrite, you will need to override the method as
    follows :

``` protected function _detectCallbackUrl() { $callbackUrl = null; if
(isset($_SERVER['HTTP_X_REWRITE_URL'])) { $callbackUrl =
$_SERVER['HTTP_X_REWRITE_URL']; } if
(isset($_SERVER['HTTP_X_ORIGINAL_URL'])) { $callbackUrl =
$_SERVER['HTTP_X_ORIGINAL_URL']; }

return $callbackUrl ?: parent::__detectCallbackUrl(); } ```

If you use an approach such as the above, make sure you also
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
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-7da5983771"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-zendframework-zend-feed package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-zendframework-zend-feed");
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
if (rpm_check(release:"FC28", reference:"php-zendframework-zend-feed-2.10.3-1.fc28")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-zendframework-zend-feed");
}
