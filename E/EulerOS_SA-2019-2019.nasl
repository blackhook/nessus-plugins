#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129212);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2018-14647",
    "CVE-2018-1000030",
    "CVE-2019-9948",
    "CVE-2019-10160"
  );

  script_name(english:"EulerOS 2.0 SP3 : python (EulerOS-SA-2019-2019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Python is an interpreted, interactive, object-oriented
    programming language, which includes modules, classes,
    exceptions, very high level dynamic data types and
    dynamic typing. Python supports interfaces to many
    system calls and libraries, as well as to various
    windowing systems.Security Fix(es):A security
    regression of CVE-2019-9636 was discovered in python,
    since commit d537ab0ff9767ef024f26246899728f0116b1ec3,
    which still allows an attacker to exploit CVE-2019-9636
    by abusing the user and password parts of a URL. When
    an application parses user-supplied URLs to store
    cookies, authentication credentials, or other kind of
    information, it is possible for an attacker to provide
    specially crafted URLs to make the application locate
    host-related information (e.g. cookies, authentication
    data) and send them to a different host than where it
    should, unlike if the URLs had been correctly parsed.
    The result of an attack may vary based on the
    application.(CVE-2019-10160)urllib in Python 2.x
    through 2.7.16 supports the local_file: scheme, which
    makes it easier for remote attackers to bypass
    protection mechanisms that blacklist file: URIs, as
    demonstrated by triggering a
    urllib.urlopen('local_file:///etc/passwd')
    call.(CVE-2019-9948)Python's elementtree C accelerator
    failed to initialise Expat's hash salt during
    initialization. This could make it easy to conduct
    denial of service attacks against Expat by constructing
    an XML document that would cause pathological hash
    collisions in Expat's internal data structures,
    consuming large amounts CPU and
    RAM.(CVE-2018-14647)python 2.7.14 is vulnerable to a
    Heap-Buffer-Overflow as well as a Heap-Use-After-Free.
    Python versions prior to 2.7.14 may also be vulnerable
    and it appears that Python 2.7.17 and prior may also be
    vulnerable however this has not been confirmed. The
    vulnerability lies when multiply threads are handling
    large amounts of data. In both cases there is
    essentially a race condition that occurs. For the
    Heap-Buffer-Overflow, Thread 2 is creating the size for
    a buffer, but Thread1 is already writing to the buffer
    without knowing how much to write. So when a large
    amount of data is being processed, it is very easy to
    cause memory corruption using a Heap-Buffer-Overflow.
    As for the Use-After-Free,
    Thread3-i1/4zMalloc-i1/4zThread1-i1/4zFree's-i1/4zThread2-Re-us
    es-Free'd Memory. The PSRT has stated that this is not
    a security vulnerability due to the fact that the
    attacker must be able to run code, however in some
    situations, such as function as a service, this
    vulnerability can potentially be used by an attacker to
    violate a trust boundary, as such the DWF feels this
    issue deserves a CVE.(CVE-2018-1000030)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?927445bd");
  script_set_attribute(attribute:"solution", value:
"Update the affected python packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9948");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tkinter");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["python-2.7.5-58.h18",
        "python-devel-2.7.5-58.h18",
        "python-libs-2.7.5-58.h18",
        "tkinter-2.7.5-58.h18"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
