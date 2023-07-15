#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131644);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2015-8035",
    "CVE-2017-0663",
    "CVE-2017-5969",
    "CVE-2017-8872",
    "CVE-2017-9048",
    "CVE-2017-18258",
    "CVE-2018-14567"
  );

  script_name(english:"EulerOS 2.0 SP2 : libxml2 (EulerOS-SA-2019-2491)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libxml2 packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A remote code execution vulnerability in libxml2 could
    enable an attacker using a specially crafted file to
    execute arbitrary code within the context of an
    unprivileged process. This issue is rated as High due
    to the possibility of remote code execution in an
    application that uses this library. Product: Android.
    Versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1,
    7.1.2. Android ID: A-37104170.(CVE-2017-0663)

  - libxml2 2.9.8, if --with-lzma is used, allows remote
    attackers to cause a denial of service (infinite loop)
    via a crafted XML file that triggers
    LZMA_MEMLIMIT_ERROR, as demonstrated by xmllint, a
    different vulnerability than CVE-2015-8035 and
    CVE-2018-9251.(CVE-2018-14567)

  - The htmlParseTryOrFinish function in HTMLparser.c in
    libxml2 2.9.4 allows attackers to cause a denial of
    service (buffer over-read) or information
    disclosure.(CVE-2017-8872)

  - libxml2 20904-GITv2.9.4-16-g0741801 is vulnerable to a
    stack-based buffer overflow. The function
    xmlSnprintfElementContent in valid.c is supposed to
    recursively dump the element content definition into a
    char buffer 'buf' of size 'size'. At the end of the
    routine, the function may strcat two more characters
    without checking whether the current strlen(buf) + 2 <
    size. This vulnerability causes programs that use
    libxml2, such as PHP, to crash.(CVE-2017-9048)

  - The xz_decomp function in xzlib.c in libxml2 2.9.1 does
    not properly detect compression errors, which allows
    context-dependent attackers to cause a denial of
    service (process hang) via crafted XML
    data.(CVE-2015-8035)

  - The xz_head function in xzlib.c in libxml2 before 2.9.6
    allows remote attackers to cause a denial of service
    (memory consumption) via a crafted LZMA file, because
    the decoder functionality does not restrict memory
    usage to what is required for a legitimate
    file.(CVE-2017-18258)

  - ** DISPUTED ** libxml2 2.9.4, when used in recover
    mode, allows remote attackers to cause a denial of
    service (NULL pointer dereference) via a crafted XML
    document. NOTE: The maintainer states 'I would disagree
    of a CVE with the Recover parsing option which should
    only be used for manual recovery at least for XML
    parser.'(CVE-2017-5969)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2491
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ee5278");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxml2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0663");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-8872");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["libxml2-2.9.1-6.3.h18",
        "libxml2-devel-2.9.1-6.3.h18",
        "libxml2-python-2.9.1-6.3.h18"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
