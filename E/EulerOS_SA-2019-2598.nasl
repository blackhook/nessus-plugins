#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132133);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-9398",
    "CVE-2017-13748",
    "CVE-2017-13751",
    "CVE-2017-6852",
    "CVE-2018-19539",
    "CVE-2018-19540",
    "CVE-2018-19541",
    "CVE-2018-19542",
    "CVE-2018-9055"
  );

  script_name(english:"EulerOS 2.0 SP3 : jasper (EulerOS-SA-2019-2598)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the jasper package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in JasPer 2.0.14. There is a
    heap-based buffer overflow of size 1 in the function
    jas_icctxtdesc_input in
    libjasper/base/jas_icc.c.(CVE-2018-19540)

  - An issue was discovered in JasPer 2.0.14. There is a
    heap-based buffer over-read of size 8 in the function
    jas_image_depalettize in
    libjasper/base/jas_image.c.(CVE-2018-19541)

  - An issue was discovered in JasPer 2.0.14. There is a
    NULL pointer dereference in the function jp2_decode in
    libjasper/jp2/jp2_dec.c, leading to a denial of
    service.(CVE-2018-19542)

  - An issue was discovered in JasPer 2.0.14. There is an
    access violation in the function jas_image_readcmpt in
    libjasper/base/jas_image.c, leading to a denial of
    service.(CVE-2018-19539)

  - Heap-based buffer overflow in the jpc_dec_decodepkt
    function in jpc_t2dec.c in JasPer 2.0.10 allows remote
    attackers to have unspecified impact via a crafted
    image.(CVE-2017-6852)

  - JasPer 2.0.14 allows denial of service via a reachable
    assertion in the function jpc_firstone in
    libjasper/jpc/jpc_math.c.(CVE-2018-9055)

  - The jpc_floorlog2 function in jpc_math.c in JasPer
    before 1.900.17 allows remote attackers to cause a
    denial of service (assertion failure) via unspecified
    vectors.(CVE-2016-9398)

  - There are lots of memory leaks in JasPer 2.0.12,
    triggered in the function jas_strdup() in
    base/jas_string.c, that will lead to a remote denial of
    service attack.(CVE-2017-13748)

  - There is a reachable assertion abort in the function
    calcstepsizes() in jpc/jpc_dec.c in JasPer 2.0.12 that
    will lead to a remote denial of service
    attack.(CVE-2017-13751)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2598
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e14c375c");
  script_set_attribute(attribute:"solution", value:
"Update the affected jasper packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19541");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:jasper-libs");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["jasper-libs-1.900.1-33.h4"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper");
}