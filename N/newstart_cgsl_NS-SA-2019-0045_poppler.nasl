#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0045. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127224);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-18267", "CVE-2018-10768", "CVE-2018-13988");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : poppler Multiple Vulnerabilities (NS-SA-2019-0045)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has poppler packages installed that are affected
by multiple vulnerabilities:

  - Poppler through 0.62 contains an out of bounds read
    vulnerability due to an incorrect memory access that is
    not mapped in its memory space, as demonstrated by
    pdfunite. This can result in memory corruption and
    denial of service. This may be exploitable when a victim
    opens a specially crafted PDF file. (CVE-2018-13988)

  - There is a NULL pointer dereference in the
    AnnotPath::getCoordsLength function in Annot.h in an
    Ubuntu package for Poppler 0.24.5. A crafted input will
    lead to a remote denial of service attack. Later Ubuntu
    packages such as for Poppler 0.41.0 are not affected.
    (CVE-2018-10768)

  - The FoFiType1C::cvtGlyph function in fofi/FoFiType1C.cc
    in Poppler through 0.64.0 allows remote attackers to
    cause a denial of service (infinite recursion) via a
    crafted PDF file, as demonstrated by pdftops.
    (CVE-2017-18267)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0045");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL poppler packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13988");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "poppler-0.26.5-20.el7",
    "poppler-cpp-0.26.5-20.el7",
    "poppler-cpp-devel-0.26.5-20.el7",
    "poppler-debuginfo-0.26.5-20.el7",
    "poppler-demos-0.26.5-20.el7",
    "poppler-devel-0.26.5-20.el7",
    "poppler-glib-0.26.5-20.el7",
    "poppler-glib-devel-0.26.5-20.el7",
    "poppler-qt-0.26.5-20.el7",
    "poppler-qt-devel-0.26.5-20.el7",
    "poppler-utils-0.26.5-20.el7"
  ],
  "CGSL MAIN 5.04": [
    "poppler-0.26.5-20.el7",
    "poppler-cpp-0.26.5-20.el7",
    "poppler-cpp-devel-0.26.5-20.el7",
    "poppler-debuginfo-0.26.5-20.el7",
    "poppler-demos-0.26.5-20.el7",
    "poppler-devel-0.26.5-20.el7",
    "poppler-glib-0.26.5-20.el7",
    "poppler-glib-devel-0.26.5-20.el7",
    "poppler-qt-0.26.5-20.el7",
    "poppler-qt-devel-0.26.5-20.el7",
    "poppler-utils-0.26.5-20.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler");
}
