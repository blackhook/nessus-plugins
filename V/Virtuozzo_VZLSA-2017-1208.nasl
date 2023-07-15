#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101464);
  script_version("1.41");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2015-5203",
    "CVE-2015-5221",
    "CVE-2016-10248",
    "CVE-2016-10249",
    "CVE-2016-10251",
    "CVE-2016-1577",
    "CVE-2016-1867",
    "CVE-2016-2089",
    "CVE-2016-2116",
    "CVE-2016-8654",
    "CVE-2016-8690",
    "CVE-2016-8691",
    "CVE-2016-8692",
    "CVE-2016-8693",
    "CVE-2016-8883",
    "CVE-2016-8884",
    "CVE-2016-8885",
    "CVE-2016-9262",
    "CVE-2016-9387",
    "CVE-2016-9388",
    "CVE-2016-9389",
    "CVE-2016-9390",
    "CVE-2016-9391",
    "CVE-2016-9392",
    "CVE-2016-9393",
    "CVE-2016-9394",
    "CVE-2016-9560",
    "CVE-2016-9583",
    "CVE-2016-9591",
    "CVE-2016-9600"
  );

  script_name(english:"Virtuozzo 6 : jasper / jasper-devel / jasper-libs / jasper-utils (VZLSA-2017-1208)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for jasper is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

JasPer is an implementation of Part 1 of the JPEG 2000 image
compression standard.

Security Fix(es) :

Multiple flaws were found in the way JasPer decoded JPEG 2000 image
files. A specially crafted file could cause an application using
JasPer to crash or, possibly, execute arbitrary code. (CVE-2016-8654,
CVE-2016-9560, CVE-2016-10249, CVE-2015-5203, CVE-2015-5221,
CVE-2016-1577, CVE-2016-8690, CVE-2016-8693, CVE-2016-8884,
CVE-2016-8885, CVE-2016-9262, CVE-2016-9591)

Multiple flaws were found in the way JasPer decoded JPEG 2000 image
files. A specially crafted file could cause an application using
JasPer to crash. (CVE-2016-1867, CVE-2016-2089, CVE-2016-2116,
CVE-2016-8691, CVE-2016-8692, CVE-2016-8883, CVE-2016-9387,
CVE-2016-9388, CVE-2016-9389, CVE-2016-9390, CVE-2016-9391,
CVE-2016-9392, CVE-2016-9393, CVE-2016-9394, CVE-2016-9583,
CVE-2016-9600, CVE-2016-10248, CVE-2016-10251)

Red Hat would like to thank Liu Bingchang (IIE) for reporting
CVE-2016-8654, CVE-2016-9583, CVE-2016-9591, and CVE-2016-9600;
Gustavo Grieco for reporting CVE-2015-5203; and Josselin Feist for
reporting CVE-2015-5221.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1208.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d954250");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-1208");
  script_set_attribute(attribute:"solution", value:
"Update the affected jasper / jasper-devel / jasper-libs / jasper-utils package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:jasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:jasper-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:jasper-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["jasper-1.900.1-21.vl6",
        "jasper-devel-1.900.1-21.vl6",
        "jasper-libs-1.900.1-21.vl6",
        "jasper-utils-1.900.1-21.vl6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper / jasper-devel / jasper-libs / jasper-utils");
}
