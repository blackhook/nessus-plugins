#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145782);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/04");

  script_cve_id(
    "CVE-2020-8619",
    "CVE-2020-8624"
  );

  script_name(english:"EulerOS 2.0 SP8 : bind (EulerOS-SA-2021-1134)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - In ISC BIND9 versions BIND 9.11.14 -> 9.11.19, BIND
    9.14.9 -> 9.14.12, BIND 9.16.0 -> 9.16.3, BIND
    Supported Preview Edition 9.11.14-S1 -> 9.11.19-S1:
    Unless a nameserver is providing authoritative service
    for one or more zones and at least one zone contains an
    empty non-terminal entry containing an asterisk ('*')
    character, this defect cannot be encountered. A
    would-be attacker who is allowed to change zone content
    could theoretically introduce such a record in order to
    exploit this condition to cause denial of service,
    though we consider the use of this vector unlikely
    because any such attack would require a significant
    privilege level and be easily traceable.(CVE-2020-8619)

  - In BIND 9.9.12 -> 9.9.13, 9.10.7 -> 9.10.8, 9.11.3 ->
    9.11.21, 9.12.1 -> 9.16.5, 9.17.0 -> 9.17.3, also
    affects 9.9.12-S1 -> 9.9.13-S1, 9.11.3-S1 -> 9.11.21-S1
    of the BIND 9 Supported Preview Edition, An attacker
    who has been granted privileges to change a specific
    subset of the zone's content could abuse these
    unintended additional privileges to update other
    contents of the zone.(CVE-2020-8624)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1134
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8eba202");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8624");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bind-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-chroot-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-export-devel-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-export-libs-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-libs-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-libs-lite-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-license-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-pkcs11-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-pkcs11-libs-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-pkcs11-utils-9.11.4-10.P2.h24.eulerosv2r8",
        "bind-utils-9.11.4-10.P2.h24.eulerosv2r8",
        "python3-bind-9.11.4-10.P2.h24.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
