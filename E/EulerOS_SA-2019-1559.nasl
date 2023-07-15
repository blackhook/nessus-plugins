#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125103);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2012-2807",
    "CVE-2015-8035",
    "CVE-2017-18258",
    "CVE-2018-14404"
  );
  script_bugtraq_id(
    54203,
    54718
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : libxml2 (EulerOS-SA-2019-1559)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libxml2 packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - This library allows to manipulate XML files. It
    includes support to read, modify and write XML and HTML
    files. There is DTDs support this includes parsing and
    validation even with complex DtDs, either at parse time
    or later once the document has been modified. The
    output can be a simple SAX stream or and in-memory DOM
    like representations.In this case one can use the
    built-in XPath and XPointer implementation to select
    sub nodes or ranges. A flexible Input/Output mechanism
    is available, with existing HTTP and FTP modules and
    combined to an URI library.

  - Security Fixi1/4^esi1/4%0:

  - Multiple integer overflows in libxml2, as used in
    Google Chrome before 20.0.1132.43 and other products,
    on 64-bit Linux platforms allow remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via unknown vectors.i1/4^CVE-2012-2807i1/4%0

  - A denial of service flaw was found in libxml2. A remote
    attacker could provide a specially crafted XML or HTML
    file that, when processed by an application using
    libxml2, would cause that application to
    crash.i1/4^CVE-2015-8035i1/4%0

  - The xz_head function in xzlib.c in libxml2 before 2.9.6
    allows remote attackers to cause a denial of service
    i1/4^memory consumptioni1/4%0 via a crafted LZMA file,
    because the decoder functionality does not restrict
    memory usage to what is required for a legitimate
    file.i1/4^CVE-2017-18258i1/4%0

  - A NULL pointer dereference vulnerability exists in the
    xpath.c:xmlXPathCompOpEvali1/4^i1/4%0 function of libxml2
    through 2.9.8 when parsing an invalid XPath expression
    in the XPATH_OP_AND or XPATH_OP_OR case. Applications
    processing untrusted XSL format inputs with the use of
    the libxml2 library may be vulnerable to a denial of
    service attack due to a crash of the
    application.i1/4^CVE-2018-14404i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1559
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2a133c6");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxml2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libxml2-2.9.1-6.3.h14",
        "libxml2-devel-2.9.1-6.3.h14",
        "libxml2-python-2.9.1-6.3.h14"];

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
