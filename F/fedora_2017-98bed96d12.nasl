#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-98bed96d12.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101920);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2016-5078",
    "CVE-2016-5133",
    "CVE-2016-5147",
    "CVE-2016-5153",
    "CVE-2016-5155",
    "CVE-2016-5161",
    "CVE-2016-5166",
    "CVE-2016-5170",
    "CVE-2016-5171",
    "CVE-2016-5172",
    "CVE-2016-5181",
    "CVE-2016-5185",
    "CVE-2016-5186",
    "CVE-2016-5187",
    "CVE-2016-5188",
    "CVE-2016-5192",
    "CVE-2016-5198",
    "CVE-2016-5205",
    "CVE-2016-5207",
    "CVE-2016-5208",
    "CVE-2016-5214",
    "CVE-2016-5215",
    "CVE-2016-5221",
    "CVE-2016-5222",
    "CVE-2016-5224",
    "CVE-2016-5225",
    "CVE-2016-9650",
    "CVE-2016-9651",
    "CVE-2016-9652",
    "CVE-2017-5006",
    "CVE-2017-5007",
    "CVE-2017-5008",
    "CVE-2017-5009",
    "CVE-2017-5010",
    "CVE-2017-5012",
    "CVE-2017-5015",
    "CVE-2017-5016",
    "CVE-2017-5017",
    "CVE-2017-5019",
    "CVE-2017-5023",
    "CVE-2017-5024",
    "CVE-2017-5025",
    "CVE-2017-5026",
    "CVE-2017-5027",
    "CVE-2017-5029",
    "CVE-2017-5033",
    "CVE-2017-5037",
    "CVE-2017-5044",
    "CVE-2017-5046",
    "CVE-2017-5047",
    "CVE-2017-5048",
    "CVE-2017-5049",
    "CVE-2017-5050",
    "CVE-2017-5051",
    "CVE-2017-5059",
    "CVE-2017-5061",
    "CVE-2017-5062",
    "CVE-2017-5065",
    "CVE-2017-5067",
    "CVE-2017-5069",
    "CVE-2017-5070",
    "CVE-2017-5071",
    "CVE-2017-5075",
    "CVE-2017-5076",
    "CVE-2017-5083",
    "CVE-2017-5089"
  );
  script_xref(name:"FEDORA", value:"2017-98bed96d12");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Fedora 24 : qt5-qtwebengine (2017-98bed96d12)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update updates QtWebEngine to a snapshot from the Qt 5.6 LTS
(long-term support) branch. This is a snapshot of the QtWebEngine that
will be included in the bugfix and security release Qt 5.6.3, but only
the QtWebEngine component is included in this update.

The update fixes the following security issues in QtWebEngine 5.6.2:
CVE-2016-5133, CVE-2016-5147, CVE-2016-5153, CVE-2016-5155,
CVE-2016-5161, CVE-2016-5166, CVE-2016-5170, CVE-2016-5171,
CVE-2016-5172, CVE-2016-5181, CVE-2016-5185, CVE-2016-5186,
CVE-2016-5187, CVE-2016-5188, CVE-2016-5192, CVE-2016-5198,
CVE-2016-5205, CVE-2016-5207, CVE-2016-5208, CVE-2016-5214,
CVE-2016-5215, CVE-2016-5221, CVE-2016-5222, CVE-2016-5224,
CVE-2016-5225, CVE-2016-9650, CVE-2016-9651, CVE-2016-9652,
CVE-2017-5006, CVE-2017-5007, CVE-2017-5008, CVE-2017-5009,
CVE-2017-5010, CVE-2017-5012, CVE-2017-5015, CVE-2017-5016,
CVE-2017-5017, CVE-2017-5019, CVE-2017-5023, CVE-2017-5024,
CVE-2017-5025, CVE-2017-5026, CVE-2017-5027, CVE-2017-5029,
CVE-2017-5033, CVE-2017-5037, CVE-2017-5044, CVE-2017-5046,
CVE-2017-5047, CVE-2017-5048, CVE-2017-5049, CVE-2017-5050,
CVE-2017-5051, CVE-2017-5059, CVE-2017-5061, CVE-2017-5062,
CVE-2017-5065, CVE-2017-5067, CVE-2017-5069, CVE-2017-5070,
CVE-2017-5071, CVE-2017-5075, CVE-2017-5076, CVE-2016-5078,
CVE-2017-5083, and CVE-2017-5089.

Other important changes include :

  - Based on Chromium 49.0.2623.111 (the version used in
    QtWebEngine 5.7.x) with security fixes from Chromium up
    to version 59.0.3071.104. (5.6.2 was based on Chromium
    45.0.2554.101 with security fixes from Chromium up to
    version 52.0.2743.116.)

  - All other bug fixes from QtWebEngine 5.7.1 have been
    backported.

See
http://code.qt.io/cgit/qt/qtwebengine.git/tree/dist/changes-5.6.3?h=5.
6 for details. (Please note that at the time of this writing, not all
security backports are listed in that file yet. The list above is
accurate.)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  # http://code.qt.io/cgit/qt/qtwebengine.git/tree/dist/changes-5.6.3?h=5.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfc84d1b");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-98bed96d12");
  script_set_attribute(attribute:"solution", value:
"Update the affected qt5-qtwebengine package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");
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
if (! preg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"qt5-qtwebengine-5.6.3-0.1.20170712gitee719ad313e564.fc24")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-qtwebengine");
}
