#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151313);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2020-8622",
    "CVE-2020-8623",
    "CVE-2021-25214",
    "CVE-2021-25215"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : bind (EulerOS-SA-2021-2092)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - In BIND 9.0.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 ->
    9.17.3, also affects 9.9.3-S1 -> 9.11.21-S1 of the BIND
    9 Supported Preview Edition, An attacker on the network
    path for a TSIG-signed request, or operating the server
    receiving the TSIG-signed request, could send a
    truncated response to that request, triggering an
    assertion failure, causing the server to exit.
    Alternately, an off-path attacker would have to
    correctly guess when a TSIG-signed request was sent,
    along with other characteristics of the packet and
    message, and spoof a truncated response to trigger an
    assertion failure, causing the server to
    exit.(CVE-2020-8622)

  - In BIND 9.10.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 ->
    9.17.3, also affects 9.10.5-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker that can
    reach a vulnerable system with a specially crafted
    query packet can trigger a crash. To be vulnerable, the
    system must: * be running BIND that was built with
    '--enable-native-pkcs11' * be signing one or more zones
    with an RSA key * be able to receive queries from a
    possible attacker(CVE-2020-8623)

  - In BIND 9.0.0 -> 9.11.29, 9.12.0 -> 9.16.13, and
    versions BIND 9.9.3-S1 -> 9.11.29-S1 and 9.16.8-S1 ->
    9.16.13-S1 of BIND Supported Preview Edition, as well
    as release versions 9.17.0 -> 9.17.11 of the BIND 9.17
    development branch, when a vulnerable version of named
    receives a query for a record triggering the flaw
    described above, the named process will terminate due
    to a failed assertion check. The vulnerability affects
    all currently maintained BIND 9 branches (9.11, 9.11-S,
    9.16, 9.16-S, 9.17) as well as all other versions of
    BIND 9.(CVE-2021-25215)

  - In BIND 9.8.5 -> 9.8.8, 9.9.3 -> 9.11.29, 9.12.0 ->
    9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and
    9.16.8-S1 -> 9.16.13-S1 of BIND 9 Supported Preview
    Edition, as well as release versions 9.17.0 -> 9.17.11
    of the BIND 9.17 development branch, when a vulnerable
    version of named receives a malformed IXFR triggering
    the flaw described above, the named process will
    terminate due to a failed assertion the next time the
    transferred secondary zone is
    refreshed.(CVE-2021-25214)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2092
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d52324b");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["bind-libs-9.9.4-61.1.h16",
        "bind-libs-lite-9.9.4-61.1.h16",
        "bind-license-9.9.4-61.1.h16",
        "bind-utils-9.9.4-61.1.h16"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
