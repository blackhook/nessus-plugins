#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125578);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-14647",
    "CVE-2019-5010"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : python (EulerOS-SA-2019-1626)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - Python is an interpreted, interactive, object-oriented
    programming language often compared to Tcl, Perl,
    Scheme or Java. Python includes modules, classes,
    exceptions, very high level dynamic data types and
    dynamic typing. Python supports interfaces to many
    system calls and libraries, as well as to various
    windowing systems (X11, Motif, Tk, Mac and
    MFC).Programmers can write new built-in modules for
    Python in C or C++. Python can be used as an extension
    language for applications that need a programmable
    interface.Note that documentation for Python is
    provided in the python-docsSecurity Fix(es): Python's
    elementtree C accelerator failed to initialise Expat's
    hash salt during initialization. This could make it
    easy to conduct denial of service attacks against Expat
    by constructing an XML document that would cause
    pathological hash collisions in Expat's internal data
    structures, consuming large amounts CPU and
    RAM.(CVE-2018-14647)An exploitable denial-of-service
    vulnerability exists in the X509 certificate parser of
    Python.org Python 2.7.11 / 3.6.6. A specially crafted
    X509 certificate can cause a NULL pointer dereference,
    resulting in a denial of service. An attacker can
    initiate or accept TLS connections using crafted
    certificates to trigger this
    vulnerability.(CVE-2019-5010)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1626
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79d01a7b");
  script_set_attribute(attribute:"solution", value:
"Update the affected python packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["python-2.7.5-69.h20",
        "python-devel-2.7.5-69.h20",
        "python-libs-2.7.5-69.h20",
        "python-tools-2.7.5-69.h20"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
