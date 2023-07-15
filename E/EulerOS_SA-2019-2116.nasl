#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130825);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-16852",
    "CVE-2018-16857",
    "CVE-2019-10197"
  );

  script_name(english:"EulerOS 2.0 SP8 : samba (EulerOS-SA-2019-2116)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in samba versions 4.9.x up to 4.9.13,
    samba 4.10.x up to 4.10.8 and samba 4.11.x up to
    4.11.0rc3, when certain parameters were set in the
    samba configuration file. An unauthenticated attacker
    could use this flaw to escape the shared directory and
    access the contents of directories outside the
    share.(CVE-2019-10197)

  - A null pointer dereference flaw was found in the Samba
    DNS Management server when used as an Active Directory
    Domain Controller. A remote attacker could use this
    flaw to cause a denial of service (application
    crash).Samba from version 4.9.0 and before version
    4.9.3 is vulnerable to a NULL pointer de-reference.
    During the processing of an DNS zone in the DNS
    management DCE/RPC server, the internal DNS server or
    the Samba DLZ plugin for BIND9, if the
    DSPROPERTY_ZONE_MASTER_SERVERS property or
    DSPROPERTY_ZONE_SCAVENGING_SERVERS property is set, the
    server will follow a NULL pointer and terminate. There
    is no further vulnerability associated with this issue,
    merely a denial of service.(CVE-2018-16852)

  - It was found that the 'bad password observation window'
    was ineffective when set to a value greater than 3
    minutes. This could allow for brute force password
    attacks in some situations.(CVE-2018-16857)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2116
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edf7d73b");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["ctdb-4.9.1-2.h11.eulerosv2r8",
        "ctdb-tests-4.9.1-2.h11.eulerosv2r8",
        "libsmbclient-4.9.1-2.h11.eulerosv2r8",
        "libwbclient-4.9.1-2.h11.eulerosv2r8",
        "python2-samba-4.9.1-2.h11.eulerosv2r8",
        "python2-samba-test-4.9.1-2.h11.eulerosv2r8",
        "python3-samba-4.9.1-2.h11.eulerosv2r8",
        "python3-samba-test-4.9.1-2.h11.eulerosv2r8",
        "samba-4.9.1-2.h11.eulerosv2r8",
        "samba-client-4.9.1-2.h11.eulerosv2r8",
        "samba-client-libs-4.9.1-2.h11.eulerosv2r8",
        "samba-common-4.9.1-2.h11.eulerosv2r8",
        "samba-common-libs-4.9.1-2.h11.eulerosv2r8",
        "samba-common-tools-4.9.1-2.h11.eulerosv2r8",
        "samba-dc-libs-4.9.1-2.h11.eulerosv2r8",
        "samba-krb5-printing-4.9.1-2.h11.eulerosv2r8",
        "samba-libs-4.9.1-2.h11.eulerosv2r8",
        "samba-pidl-4.9.1-2.h11.eulerosv2r8",
        "samba-test-4.9.1-2.h11.eulerosv2r8",
        "samba-test-libs-4.9.1-2.h11.eulerosv2r8",
        "samba-winbind-4.9.1-2.h11.eulerosv2r8",
        "samba-winbind-clients-4.9.1-2.h11.eulerosv2r8",
        "samba-winbind-krb5-locator-4.9.1-2.h11.eulerosv2r8",
        "samba-winbind-modules-4.9.1-2.h11.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
