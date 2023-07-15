#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124911);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-12150",
    "CVE-2017-12151",
    "CVE-2017-12163",
    "CVE-2017-14746",
    "CVE-2017-15275",
    "CVE-2018-1050",
    "CVE-2018-10858"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : samba (EulerOS-SA-2019-1408)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A null pointer dereference flaw was found in Samba RPC
    external printer service. An attacker could use this
    flaw to cause the printer spooler service to
    crash.(CVE-2018-1050)

  - A heap-buffer overflow was found in the way samba
    clients processed extra long filename in a directory
    listing. A malicious samba server could use this flaw
    to cause arbitrary code execution on a samba client.
    (CVE-2018-10858)

  - A use-after-free flaw was found in the way samba
    servers handled certain SMB1 requests. An
    unauthenticated attacker could send specially-crafted
    SMB1 requests to cause the server to crash or execute
    arbitrary code.(CVE-2017-14746)

  - A memory disclosure flaw was found in samba. An
    attacker could retrieve parts of server memory, which
    could contain potentially sensitive data, by sending
    specially-crafted requests to the samba
    server.(CVE-2017-15275)

  - It was found that samba did not enforce 'SMB signing'
    when certain configuration options were enabled. A
    remote attacker could launch a man-in-the-middle attack
    and retrieve information in plain-text.(CVE-2017-12150)

  - A flaw was found in the way samba client used
    encryption with the max protocol set as SMB3. The
    connection could lose the requirement for signing and
    encrypting to any DFS redirects, allowing an attacker
    to read or alter the contents of the connection via a
    man-in-the-middle attack.(CVE-2017-12151)

  - An information leak flaw was found in the way SMB1
    protocol was implemented by Samba. A malicious client
    could use this flaw to dump server memory contents to a
    file on the samba share or to a shared printer, though
    the exact area of server memory cannot be controlled by
    the attacker.(CVE-2017-12163)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1408
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9766417c");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["libsmbclient-4.7.1-9.h2",
        "libwbclient-4.7.1-9.h2",
        "samba-client-libs-4.7.1-9.h2",
        "samba-common-4.7.1-9.h2",
        "samba-common-libs-4.7.1-9.h2",
        "samba-common-tools-4.7.1-9.h2",
        "samba-libs-4.7.1-9.h2"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
