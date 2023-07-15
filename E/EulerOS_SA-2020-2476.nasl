#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142530);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2020-10730",
    "CVE-2020-10745",
    "CVE-2020-10760",
    "CVE-2020-14303"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.6 : samba (EulerOS-SA-2020-2476)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A use-after-free flaw was found in all samba LDAP
    server versions before 4.10.17, before 4.11.11, before
    4.12.4 used in a AC DC configuration. A Samba LDAP user
    could use this flaw to crash samba.(CVE-2020-10760)

  - A flaw was found in all Samba versions before 4.10.17,
    before 4.11.11 and before 4.12.4 in the way it
    processed NetBios over TCP/IP. This flaw allows a
    remote attacker could to cause the Samba server to
    consume excessive CPU use, resulting in a denial of
    service. This highest threat from this vulnerability is
    to system availability.(CVE-2020-10745)

  - A NULL pointer dereference, or possible use-after-free
    flaw was found in Samba AD LDAP server in versions
    before 4.10.17, before 4.11.11 and before 4.12.4.
    Although some versions of Samba shipped with Red Hat
    Enterprise Linux do not support Samba in AD mode, the
    affected code is shipped with the libldb package. This
    flaw allows an authenticated user to possibly trigger a
    use-after-free or NULL pointer dereference. The highest
    threat from this vulnerability is to system
    availability.(CVE-2020-10730)

  - A flaw was found in the AD DC NBT server in all Samba
    versions before 4.10.17, before 4.11.11 and before
    4.12.4. A samba user could send an empty UDP packet to
    cause the samba server to crash.(CVE-2020-14303)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2476
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac10146a");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10745");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.6");
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
if (uvp != "3.0.6.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libsmbclient-4.7.1-9.h20.eulerosv2r7",
        "libwbclient-4.7.1-9.h20.eulerosv2r7",
        "samba-4.7.1-9.h20.eulerosv2r7",
        "samba-client-4.7.1-9.h20.eulerosv2r7",
        "samba-client-libs-4.7.1-9.h20.eulerosv2r7",
        "samba-common-4.7.1-9.h20.eulerosv2r7",
        "samba-common-libs-4.7.1-9.h20.eulerosv2r7",
        "samba-common-tools-4.7.1-9.h20.eulerosv2r7",
        "samba-libs-4.7.1-9.h20.eulerosv2r7",
        "samba-python-4.7.1-9.h20.eulerosv2r7",
        "samba-winbind-4.7.1-9.h20.eulerosv2r7",
        "samba-winbind-clients-4.7.1-9.h20.eulerosv2r7",
        "samba-winbind-modules-4.7.1-9.h20.eulerosv2r7"];

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
