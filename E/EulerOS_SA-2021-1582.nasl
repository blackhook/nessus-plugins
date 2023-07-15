#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147082);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/08");

  script_cve_id(
    "CVE-2020-24659"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : gnutls (EulerOS-SA-2021-1582)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the gnutls packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerability :

  - An issue was discovered in GnuTLS before 3.6.15. A
    server can trigger a NULL pointer dereference in a TLS
    1.3 client if a no_renegotiation alert is sent with
    unexpected timing, and then an invalid second handshake
    occurs. The crash happens in the application's error
    handling path, where the gnutls_deinit function is
    called after detecting a handshake
    failure.(CVE-2020-24659)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1582
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?488e15fc");
  script_set_attribute(attribute:"solution", value:
"Update the affected gnutls package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-dane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["gnutls-3.6.7-1.h8.eulerosv2r8",
        "gnutls-c++-3.6.7-1.h8.eulerosv2r8",
        "gnutls-dane-3.6.7-1.h8.eulerosv2r8",
        "gnutls-devel-3.6.7-1.h8.eulerosv2r8",
        "gnutls-utils-3.6.7-1.h8.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls");
}
