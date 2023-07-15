#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-a7a488d8d0.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101779);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2017-5070",
    "CVE-2017-5071",
    "CVE-2017-5075",
    "CVE-2017-5076",
    "CVE-2017-5077",
    "CVE-2017-5078",
    "CVE-2017-5079",
    "CVE-2017-5083",
    "CVE-2017-5088",
    "CVE-2017-5089"
  );
  script_xref(name:"FEDORA", value:"2017-a7a488d8d0");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Fedora 25 : qt5-qtwebengine (2017-a7a488d8d0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update updates QtWebEngine to the 5.9.1 release, a security and
bugfix release from the 5.9 branch. QtWebEngine 5.9.1 is part of the
Qt 5.9.1 release, but only the QtWebEngine component is included in
this update.

The update fixes the following security issues in QtWebEngine 5.9.0:
CVE-2017-5070, CVE-2017-5071, CVE-2017-5075, CVE-2017-5076,
CVE-2017-5077, CVE-2017-5078, CVE-2017-5079, CVE-2017-5083,
CVE-2017-5088, and CVE-2017-5089 (security fixes from Chromium up to
version 59.0.3071.104).

Other notable bugfixes include :

  - [QTBUG-59690] Fixed issue with drops

  - [QTBUG-60588] Fixed error in updating user-agent and
    accept-language

  - [QTBUG-61047] Fixed assert in URLRequestContextGetterQt

  - [QTBUG-61186] Fixed cancellation of upload folder
    dialogs

  - [QTBUG-57675] Fixed
    WebEngineNewViewRequest::requestedUrl when opening
    window from JavaScript

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-a7a488d8d0");
  script_set_attribute(attribute:"solution", value:
"Update the affected qt5-qtwebengine package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"qt5-qtwebengine-5.9.1-1.fc25")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-qtwebengine");
}
