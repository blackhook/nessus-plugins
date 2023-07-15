#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124935);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2014-2856",
    "CVE-2014-3537",
    "CVE-2014-5030",
    "CVE-2014-5031",
    "CVE-2014-9679",
    "CVE-2015-1158",
    "CVE-2015-1159",
    "CVE-2017-18190"
  );
  script_bugtraq_id(
    66788,
    68788,
    68846,
    68847,
    72594,
    75098,
    75106
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : cups (EulerOS-SA-2019-1432)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the cups package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A cross-site scripting flaw was found in the cups web
    templating engine. An attacker could use this flaw to
    bypass the default configuration settings that bind the
    CUPS scheduler to the 'localhost' or loopback
    interface.(CVE-2015-1159)

  - It was discovered that CUPS allowed certain users to
    create symbolic links in certain directories under
    /var/cache/cups/. A local user with the 'lp' group
    privileges could use this flaw to read the contents of
    arbitrary files on the system or, potentially, escalate
    their privileges on the system.(CVE-2014-5031)

  - A string reference count bug was found in cupsd,
    causing premature freeing of string objects. An
    attacker could submit a malicious print job that
    exploits this flaw to dismantle ACLs protecting
    privileged operations, allowing a replacement
    configuration file to be uploaded, which in turn
    allowed the attacker to run arbitrary code on the CUPS
    server.(CVE-2015-1158)

  - A cross-site scripting (XSS) flaw was found in the CUPS
    web interface. An attacker could use this flaw to
    perform a cross-site scripting attack against users of
    the CUPS web interface.(CVE-2014-2856)

  - A localhost.localdomain whitelist entry in valid_host()
    in scheduler/client.c in CUPS before 2.2.2 allows
    remote attackers to execute arbitrary IPP commands by
    sending POST requests to the CUPS daemon in conjunction
    with DNS rebinding. The localhost.localdomain name is
    often resolved via a DNS server (neither the OS nor the
    web browser is responsible for ensuring that
    localhost.localdomain is 127.0.0.1).(CVE-2017-18190)

  - It was discovered that CUPS allowed certain users to
    create symbolic links in certain directories under
    /var/cache/cups/. A local user with the 'lp' group
    privileges could use this flaw to read the contents of
    arbitrary files on the system or, potentially, escalate
    their privileges on the system.(CVE-2014-5030)

  - It was discovered that CUPS allowed certain users to
    create symbolic links in certain directories under
    /var/cache/cups/. A local user with the 'lp' group
    privileges could use this flaw to read the contents of
    arbitrary files on the system or, potentially, escalate
    their privileges on the system.(CVE-2014-3537)

  - An integer overflow flaw, leading to a heap-based
    buffer overflow, was found in the way CUPS handled
    compressed raster image files. An attacker could create
    a specially crafted image file that, when passed via
    the CUPS Raster filter, could cause the CUPS filter to
    crash.(CVE-2014-9679)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1432
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f658fc1a");
  script_set_attribute(attribute:"solution", value:
"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:cups-libs");
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

pkgs = ["cups-libs-1.6.3-35.h2.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups");
}
