#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131873);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-4549",
    "CVE-2014-0190",
    "CVE-2015-0295",
    "CVE-2015-1858",
    "CVE-2015-1859",
    "CVE-2015-1860",
    "CVE-2018-15518",
    "CVE-2018-19871",
    "CVE-2018-19872"
  );
  script_bugtraq_id(
    64418,
    67087,
    73029,
    74302,
    74307,
    74309,
    74310
  );

  script_name(english:"EulerOS 2.0 SP2 : qt (EulerOS-SA-2019-2381)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qt packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - QXmlSimpleReader in Qt before 5.2 allows
    context-dependent attackers to cause a denial of
    service (memory consumption) via an XML Entity
    Expansion (XEE) attack.(CVE-2013-4549)

  - An issue was discovered in Qt before 5.11.3. There is
    QTgaFile Uncontrolled Resource
    Consumption.(CVE-2018-19871)

  - QXmlStream in Qt 5.x before 5.11.3 has a double-free or
    corruption during parsing of a specially crafted
    illegal XML document.(CVE-2018-15518)

  - An issue was discovered in Qt 5.11. A malformed PPM
    image causes a division by zero and a crash in
    qppmhandler.cpp.(CVE-2018-19872)

  - Multiple buffer overflows in gui/image/qbmphandler.cpp
    in the QtBase module in Qt before 4.8.7 and 5.x before
    5.4.2 allow remote attackers to cause a denial of
    service (segmentation fault and crash) and possibly
    execute arbitrary code via a crafted BMP
    image.(CVE-2015-1858)

  - Multiple buffer overflows in
    plugins/imageformats/ico/qicohandler.cpp in the QtBase
    module in Qt before 4.8.7 and 5.x before 5.4.2 allow
    remote attackers to cause a denial of service
    (segmentation fault and crash) and possibly execute
    arbitrary code via a crafted ICO image.(CVE-2015-1859)

  - Multiple buffer overflows in gui/image/qgifhandler.cpp
    in the QtBase module in Qt before 4.8.7 and 5.x before
    5.4.2 allow remote attackers to cause a denial of
    service (segmentation fault) and possibly execute
    arbitrary code via a crafted GIF image.(CVE-2015-1860)

  - The BMP decoder in QtGui in QT before 5.5 does not
    properly calculate the masks used to extract the color
    components, which allows remote attackers to cause a
    denial of service (divide-by-zero and crash) via a
    crafted BMP file.(CVE-2015-0295)

  - The GIF decoder in QtGui in Qt before 5.3 allows remote
    attackers to cause a denial of service (NULL pointer
    dereference) via invalid width and height values in a
    GIF image.(CVE-2014-0190)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2381
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?951c4700");
  script_set_attribute(attribute:"solution", value:
"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15518");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qt-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qt-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qt-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qt-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["qt-4.8.5-12.h6",
        "qt-devel-4.8.5-12.h6",
        "qt-mysql-4.8.5-12.h6",
        "qt-odbc-4.8.5-12.h6",
        "qt-postgresql-4.8.5-12.h6",
        "qt-x11-4.8.5-12.h6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt");
}
