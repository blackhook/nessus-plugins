#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140322);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-16860",
    "CVE-2020-10745",
    "CVE-2020-10760",
    "CVE-2020-14303"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : samba (EulerOS-SA-2020-1952)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The samba-libs package contains the libraries needed by
    programs that link against the SMB, RPC and other
    protocols provided by the Samba suite. Security
    Fix(es):A flaw was found in samba's Heimdal KDC
    implementation, versions 4.8.x up to, excluding 4.8.12,
    4.9.x up to, excluding 4.9.8 and 4.10.x up to,
    excluding 4.10.3, when used in AD DC mode. A man in the
    middle attacker could use this flaw to intercept the
    request to the KDC and replace the user name
    (principal) in the request with any desired user name
    (principal) that exists in the KDC effectively
    obtaining a ticket for that principal.(CVE-2018-16860)A
    flaw was found in the AD DC NBT server in all Samba
    versions before 4.10.17, before 4.11.11 and before
    4.12.4. A samba user could send an empty UDP packet to
    cause the samba server to crash.(CVE-2020-14303)A NULL
    pointer dereference, or possible use-after-free flaw
    was found in the Samba AD LDAP server. Although some
    versions of Samba shipped with Red Hat Enterprise Linux
    do not support Samba in AD mode, the affected code is
    shipped with the libldb package. This flaw allows an
    authenticated user to possibly trigger a use-after-free
    or NULL pointer dereference. The highest threat from
    this vulnerability is to system
    availability.(CVE-2020-10730)A flaw was found in Samba
    in the way it processed NetBios over TCP/IP. This flaw
    allows a remote attacker could to cause the Samba
    server to consume excessive CPU use, resulting in a
    denial of service. This highest threat from this
    vulnerability is to system
    availability.(CVE-2020-10745)A use-after-free flaw was
    found in all samba LDAP server versions before 4.10.17,
    before 4.11.11, before 4.12.4 used in a AC DC
    configuration. A Samba LDAP user could use this flaw to
    crash samba.(CVE-2020-10760)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1952
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72daa4cb");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16860");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["libsmbclient-4.7.1-9.h20",
        "libwbclient-4.7.1-9.h20",
        "samba-client-libs-4.7.1-9.h20",
        "samba-common-4.7.1-9.h20",
        "samba-common-libs-4.7.1-9.h20",
        "samba-common-tools-4.7.1-9.h20",
        "samba-libs-4.7.1-9.h20"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
