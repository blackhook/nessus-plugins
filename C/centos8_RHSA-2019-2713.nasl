##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2019:2713. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145631);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/23");

  script_cve_id(
    "CVE-2018-18897",
    "CVE-2018-20481",
    "CVE-2018-20551",
    "CVE-2018-20650",
    "CVE-2018-20662",
    "CVE-2019-7310",
    "CVE-2019-9200",
    "CVE-2019-9631",
    "CVE-2019-9903",
    "CVE-2019-9959",
    "CVE-2019-10871",
    "CVE-2019-12293"
  );
  script_bugtraq_id(
    106321,
    106459,
    106659,
    106829,
    107172,
    107560,
    107862,
    108457,
    109342
  );
  script_xref(name:"RHSA", value:"2019:2713");

  script_name(english:"CentOS 8 : poppler (CESA-2019:2713)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2019:2713 advisory.

  - poppler: memory leak in GfxColorSpace::setDisplayProfile in GfxState.cc (CVE-2018-18897)

  - poppler: NULL pointer dereference in the XRef::getEntry in XRef.cc (CVE-2018-20481)

  - poppler: reachable Object::getString assertion in AnnotRichMedia class in Annot.c (CVE-2018-20551)

  - poppler: reachable Object::dictLookup assertion in FileSpec class in FileSpec.cc (CVE-2018-20650)

  - poppler: SIGABRT PDFDoc::setup class in PDFDoc.cc (CVE-2018-20662)

  - poppler: heap-based buffer over-read in function PSOutputDev::checkPageSlice in PSOutputDev.cc
    (CVE-2019-10871)

  - poppler: heap-based buffer over-read in JPXStream::init in JPEG2000Stream.cc (CVE-2019-12293)

  - poppler: heap-based buffer over-read in XRef::getEntry in XRef.cc (CVE-2019-7310)

  - poppler: heap-based buffer overflow in function ImageStream::getLine() in Stream.cc (CVE-2019-9200)

  - poppler: heap-based buffer over-read in function downsample_row_box_filter in CairoRescaleBox.cc
    (CVE-2019-9631)

  - poppler: stack consumption in function Dict::find() in Dict.cc (CVE-2019-9903)

  - poppler: integer overflow in JPXStream::init function leading to memory consumption (CVE-2019-9959)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:2713");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9631");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-cpp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:poppler-utils");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'poppler-0.66.0-11.el8_0.12', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-0.66.0-11.el8_0.12', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-0.66.0-11.el8_0.12', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-0.66.0-11.el8_0.12', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-devel-0.66.0-11.el8_0.12', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-cpp-devel-0.66.0-11.el8_0.12', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-devel-0.66.0-11.el8_0.12', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-devel-0.66.0-11.el8_0.12', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-0.66.0-11.el8_0.12', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-0.66.0-11.el8_0.12', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-devel-0.66.0-11.el8_0.12', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-glib-devel-0.66.0-11.el8_0.12', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt5-0.66.0-11.el8_0.12', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt5-0.66.0-11.el8_0.12', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt5-devel-0.66.0-11.el8_0.12', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-qt5-devel-0.66.0-11.el8_0.12', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-utils-0.66.0-11.el8_0.12', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'poppler-utils-0.66.0-11.el8_0.12', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'poppler / poppler-cpp / poppler-cpp-devel / poppler-devel / etc');
}
