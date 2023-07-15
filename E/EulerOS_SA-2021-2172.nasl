#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151378);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id(
    "CVE-2020-12662",
    "CVE-2020-12663",
    "CVE-2020-28935"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : unbound (EulerOS-SA-2021-2172)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the unbound package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - NLnet Labs Unbound, up to and including version 1.12.0,
    and NLnet Labs NSD, up to and including version 4.3.3,
    contain a local vulnerability that would allow for a
    local symlink attack. When writing the PID file,
    Unbound and NSD create the file if it is not there, or
    open an existing file for writing. In case the file was
    already present, they would follow symlinks if the file
    happened to be a symlink instead of a regular file. An
    additional chown of the file would then take place
    after it was written, making the user Unbound/NSD is
    supposed to run as the new owner of the file. If an
    attacker has local access to the user Unbound/NSD runs
    as, she could create a symlink in place of the PID file
    pointing to a file that she would like to erase. If
    then Unbound/NSD is killed and the PID file is not
    cleared, upon restarting with root privileges,
    Unbound/NSD will rewrite any file pointed at by the
    symlink. This is a local vulnerability that could
    create a Denial of Service of the system Unbound/NSD is
    running on. It requires an attacker having access to
    the limited permission user Unbound/NSD runs as and
    point through the symlink to a critical file on the
    system.(CVE-2020-28935)

  - Unbound before 1.10.1 has Insufficient Control of
    Network Message Volume, aka an 'NXNSAttack' issue. This
    is triggered by random subdomains in the NSDNAME in NS
    records.(CVE-2020-12662)

  - Unbound before 1.10.1 has an infinite loop via
    malformed DNS answers received from upstream
    servers.(CVE-2020-12663)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2172
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bb71aaf");
  script_set_attribute(attribute:"solution", value:
"Update the affected unbound packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
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
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["unbound-libs-1.6.6-1.h4.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "unbound");
}
