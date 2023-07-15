#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131652);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-7511",
    "CVE-2017-7515",
    "CVE-2017-9406",
    "CVE-2017-9408",
    "CVE-2018-19149",
    "CVE-2019-9959"
  );

  script_name(english:"EulerOS 2.0 SP2 : poppler (EulerOS-SA-2019-2499)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the poppler packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - poppler since version 0.17.3 has been vulnerable to
    NULL pointer dereference in pdfunite triggered by
    specially crafted documents.(CVE-2017-7511)

  - poppler through version 0.55.0 is vulnerable to an
    uncontrolled recursion in pdfunite resulting into
    potential denial-of-service.(CVE-2017-7515)

  - Poppler before 0.70.0 has a NULL pointer dereference in
    _poppler_attachment_new when called from
    poppler_annot_file_attachment_get_attachment.(CVE-2018-
    19149)

  - In Poppler 0.54.0, a memory leak vulnerability was
    found in the function gmalloc in gmem.cc, which allows
    attackers to cause a denial of service via a crafted
    file.(CVE-2017-9406)

  - In Poppler 0.54.0, a memory leak vulnerability was
    found in the function Object::initArray in Object.cc,
    which allows attackers to cause a denial of service via
    a crafted file.(CVE-2017-9408)

  - The JPXStream::init function in Poppler 0.78.0 and
    earlier doesn't check for negative values of stream
    length, leading to an Integer Overflow, thereby making
    it possible to allocate a large memory chunk on the
    heap, with a size controlled by an attacker, as
    demonstrated by pdftocairo.(CVE-2019-9959)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2499
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44f7dadb");
  script_set_attribute(attribute:"solution", value:
"Update the affected poppler packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler-utils");
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

pkgs = ["poppler-0.26.5-17.h18",
        "poppler-glib-0.26.5-17.h18",
        "poppler-qt-0.26.5-17.h18",
        "poppler-utils-0.26.5-17.h18"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler");
}
