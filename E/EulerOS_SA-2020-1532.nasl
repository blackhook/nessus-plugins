#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136235);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-1932",
    "CVE-2014-1933",
    "CVE-2014-3007",
    "CVE-2014-3589",
    "CVE-2016-4009",
    "CVE-2019-16865",
    "CVE-2020-5312",
    "CVE-2020-5313"
  );
  script_bugtraq_id(
    65511,
    65513,
    67150,
    69352
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : python-pillow (EulerOS-SA-2020-1532)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-pillow package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - Integer overflow in the ImagingResampleHorizontal
    function in libImaging/Resample.c in Pillow before
    3.1.1 allows remote attackers to have unspecified
    impact via negative values of the new size, which
    triggers a heap-based buffer overflow.(CVE-2016-4009)

  - An issue was discovered in urllib2 in Python 2.x
    through 2.7.17 and urllib in Python 3.x through 3.8.0.
    CRLF injection is possible if the attacker controls a
    url parameter, as demonstrated by the first argument to
    urllib.request.urlopen with \r\n (specifically in the
    host component of a URL) followed by an HTTP header.
    This is similar to the CVE-2019-9740 query string issue
    and the CVE-2019-9947 path string issue. (This is not
    exploitable when glibc has CVE-2016-10739
    fixed.)(CVE-2014-3589)

  - Python Image Library (PIL) 1.1.7 and earlier and Pillow
    2.3 might allow remote attackers to execute arbitrary
    commands via shell metacharacters in unspecified
    vectors related to CVE-2014-1932, possibly
    JpegImagePlugin.py.(CVE-2014-3007)

  - The documentation XML-RPC server in Python through
    2.7.16, 3.x through 3.6.9, and 3.7.x through 3.7.4 has
    XSS via the server_title field. This occurs in
    Lib/DocXMLRPCServer.py in Python 2.x, and in
    Lib/xmlrpc/server.py in Python 3.x. If set_server_title
    is called with untrusted input, arbitrary JavaScript
    can be delivered to clients that visit the http URL for
    this server.(CVE-2014-1933)

  - Directory traversal vulnerability in the (1) extract
    and (2) extractall functions in the tarfile module in
    Python allows user-assisted remote attackers to
    overwrite arbitrary files via a .. (dot dot) sequence
    in filenames in a TAR archive, a related issue to
    CVE-2001-1267.(CVE-2014-1932)

  - An issue was discovered in Pillow before 6.2.0. When
    reading specially crafted invalid image files, the
    library can either allocate very large amounts of
    memory or take an extremely long period of time to
    process the image.(CVE-2019-16865)

  - libImaging/FliDecode.c in Pillow before 6.2.2 has an
    FLI buffer overflow.(CVE-2020-5313)

  - libImaging/PcxDecode.c in Pillow before 6.2.2 has a PCX
    P mode buffer overflow.(CVE-2020-5312)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1532
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1ea3d72");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-pillow packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4009");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-pillow");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["python-pillow-2.0.0-19.h6.gitd1c6db8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pillow");
}
