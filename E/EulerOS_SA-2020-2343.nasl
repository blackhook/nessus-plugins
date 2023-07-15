#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142342);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2020-11089",
    "CVE-2020-11098",
    "CVE-2020-11522",
    "CVE-2020-11525",
    "CVE-2020-13397",
    "CVE-2020-13398",
    "CVE-2020-4033"
  );

  script_name(english:"EulerOS 2.0 SP2 : freerdp (EulerOS-SA-2020-2343)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the freerdp packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - libfreerdp/gdi/gdi.c in FreeRDP > 1.0 through 2.0.0-rc4
    has an Out-of-bounds Read.(CVE-2020-11522)

  - libfreerdp/cache/bitmap.c in FreeRDP versions > 1.0
    through 2.0.0-rc4 has an Out of bounds
    read.(CVE-2020-11525)

  - An issue was discovered in FreeRDP before 2.1.1. An
    out-of-bounds (OOB) read vulnerability has been
    detected in security_fips_decrypt in
    libfreerdp/core/security.c due to an uninitialized
    value.(CVE-2020-13397)

  - An issue was discovered in FreeRDP before 2.1.1. An
    out-of-bounds (OOB) write vulnerability has been
    detected in crypto_rsa_common in
    libfreerdp/crypto/crypto.c.(CVE-2020-13398)

  - In FreeRDP before 2.1.0, there is an out-of-bound read
    in irp functions (parallel_process_irp_create,
    serial_process_irp_create, drive_process_irp_write,
    printer_process_irp_write, rdpei_recv_pdu,
    serial_process_irp_write). This has been fixed in
    2.1.0.(CVE-2020-11089)

  - In FreeRDP before version 2.1.2, there is an out of
    bounds read in RLEDECOMPRESS. All FreeRDP based clients
    with sessions with color depth < 32 are affected. This
    is fixed in version 2.1.2.(CVE-2020-4033)

  - In FreeRDP before version 2.1.2, there is an
    out-of-bound read in glyph_cache_put. This affects all
    FreeRDP clients with `+glyph-cache` option enabled This
    is fixed in version 2.1.2.(CVE-2020-11098)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2343
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc384e6c");
  script_set_attribute(attribute:"solution", value:
"Update the affected freerdp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["freerdp-1.0.2-6.1.h8",
        "freerdp-libs-1.0.2-6.1.h8",
        "freerdp-plugins-1.0.2-6.1.h8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp");
}
