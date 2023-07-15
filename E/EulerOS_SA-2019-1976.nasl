#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129133);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-16858",
    "CVE-2019-9848",
    "CVE-2019-9850",
    "CVE-2019-9851",
    "CVE-2019-9852"
  );

  script_name(english:"EulerOS 2.0 SP5 : libreoffice (EulerOS-SA-2019-1976)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libreoffice packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - libreoffice: Arbitrary python functions in arbitrary
    modules on the filesystem can be executed without
    warning (CVE-2018-16858)

  - LibreOffice has a feature where documents can specify
    that pre-installed scripts can be executed on various
    document events such as mouse-over, etc. LibreOffice is
    typically also bundled with LibreLogo, a programmable
    turtle vector graphics script, which can be manipulated
    into executing arbitrary python commands. By using the
    document event feature to trigger LibreLogo to execute
    python contained within a document a malicious document
    could be constructed which would execute arbitrary
    python commands silently without warning. In the fixed
    versions, LibreLogo cannot be called from a document
    event handler. This issue affects: Document Foundation
    LibreOffice versions prior to 6.2.5.(CVE-2019-9848)

  - LibreOffice is typically bundled with LibreLogo, a
    programmable turtle vector graphics script, which can
    execute arbitrary python commands contained with the
    document it is launched from. LibreOffice also has a
    feature where documents can specify that pre-installed
    scripts can be executed on various document script
    events such as mouse-over, etc. Protection was added,
    to address CVE-2019-9848, to block calling LibreLogo
    from script event handers. However an insufficient url
    validation vulnerability in LibreOffice allowed
    malicious to bypass that protection and again trigger
    calling LibreLogo from script event handlers. This
    issue affects: Document Foundation LibreOffice versions
    prior to 6.2.6.(CVE-2019-9850)

  - LibreOffice is typically bundled with LibreLogo, a
    programmable turtle vector graphics script, which can
    execute arbitrary python commands contained with the
    document it is launched from. Protection was added, to
    address CVE-2019-9848, to block calling LibreLogo from
    document event script handers, e.g. mouse over. However
    LibreOffice also has a separate feature where documents
    can specify that pre-installed scripts can be executed
    on various global script events such as document-open,
    etc. In the fixed versions, global script event
    handlers are validated equivalently to document script
    event handlers. This issue affects: Document Foundation
    LibreOffice versions prior to 6.2.6.(CVE-2019-9851)

  - LibreOffice has a feature where documents can specify
    that pre-installed macros can be executed on various
    script events such as mouse-over, document-open etc.
    Access is intended to be restricted to scripts under
    the share/Scripts/python, user/Scripts/python
    sub-directories of the LibreOffice install. Protection
    was added, to address CVE-2018-16858, to avoid a
    directory traversal attack where scripts in arbitrary
    locations on the file system could be executed. However
    this new protection could be bypassed by a URL encoding
    attack. In the fixed versions, the parsed url
    describing the script location is correctly encoded
    before further processing. This issue affects: Document
    Foundation LibreOffice versions prior to
    6.2.6.(CVE-2019-9852)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1976
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a47f6df");
  script_set_attribute(attribute:"solution", value:
"Update the affected libreoffice packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LibreOffice Macro Python Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-ure-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libreofficekit");
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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["autocorr-en-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-calc-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-core-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-data-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-draw-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-filters-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-graphicfilter-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-gtk2-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-gtk3-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-impress-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-langpack-en-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-math-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-opensymbol-fonts-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-pdfimport-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-pyuno-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-ure-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-ure-common-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-writer-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-x11-5.3.6.1-10.h2.eulerosv2r7",
        "libreoffice-xsltfilter-5.3.6.1-10.h2.eulerosv2r7",
        "libreofficekit-5.3.6.1-10.h2.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice");
}
