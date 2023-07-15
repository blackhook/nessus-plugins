#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134734);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-8872",
    "CVE-2017-9048",
    "CVE-2017-9049",
    "CVE-2017-9050",
    "CVE-2018-14567",
    "CVE-2018-9251"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : libxml2 (EulerOS-SA-2020-1268)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libxml2 packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - libxml2 20904-GITv2.9.4-16-g0741801 is vulnerable to a
    heap-based buffer over-read in the xmlDictAddString
    function in dict.c. This vulnerability causes programs
    that use libxml2, such as PHP, to crash. This
    vulnerability exists because of an incomplete fix for
    CVE-2016-1839.(CVE-2017-9050)

  - libxml2 20904-GITv2.9.4-16-g0741801 is vulnerable to a
    heap-based buffer over-read in the
    xmlDictComputeFastKey function in dict.c. This
    vulnerability causes programs that use libxml2, such as
    PHP, to crash. This vulnerability exists because of an
    incomplete fix for libxml2 Bug 759398.(CVE-2017-9049)

  - libxml2 20904-GITv2.9.4-16-g0741801 is vulnerable to a
    stack-based buffer overflow. The function
    xmlSnprintfElementContent in valid.c is supposed to
    recursively dump the element content definition into a
    char buffer 'buf' of size 'size'. At the end of the
    routine, the function may strcat two more characters
    without checking whether the current strlen(buf) + 2 <
    size. This vulnerability causes programs that use
    libxml2, such as PHP, to crash.(CVE-2017-9048)

  - The htmlParseTryOrFinish function in HTMLparser.c in
    libxml2 2.9.4 allows attackers to cause a denial of
    service (buffer over-read) or information
    disclosure.(CVE-2017-8872)

  - The xz_decomp function in xzlib.c in libxml2 2.9.8, if
    --with-lzma is used, allows remote attackers to cause a
    denial of service (infinite loop) via a crafted XML
    file that triggers LZMA_MEMLIMIT_ERROR, as demonstrated
    by xmllint, a different vulnerability than
    CVE-2015-8035.(CVE-2018-9251)

  - libxml2 2.9.8, if --with-lzma is used, allows remote
    attackers to cause a denial of service (infinite loop)
    via a crafted XML file that triggers
    LZMA_MEMLIMIT_ERROR, as demonstrated by xmllint, a
    different vulnerability than CVE-2015-8035 and
    CVE-2018-9251.(CVE-2018-14567)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1268
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?814b9c2e");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxml2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libxml2-2.9.1-6.3.h17",
        "libxml2-devel-2.9.1-6.3.h17",
        "libxml2-python-2.9.1-6.3.h17"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
