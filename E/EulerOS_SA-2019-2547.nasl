#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131821);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-10218", "CVE-2019-14833", "CVE-2019-14847");

  script_name(english:"EulerOS 2.0 SP5 : samba (EulerOS-SA-2019-2547)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the samba packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the samba client, all samba
    versions before samba 4.11.2, 4.10.10 and 4.9.15, where
    a malicious server can supply a pathname to the client
    with separators. This could allow the client to access
    files and folders outside of the SMB network pathnames.
    An attacker could use this vulnerability to create
    files outside of the current working directory using
    the privileges of the client user.(CVE-2019-10218)

  - A flaw was found in Samba, all versions starting samba
    4.5.0 before samba 4.9.15, samba 4.10.10, samba 4.11.2,
    in the way it handles a user password change or a new
    password for a samba user. The Samba Active Directory
    Domain Controller can be configured to use a custom
    script to check for password complexity. This
    configuration can fail to verify password complexity
    when non-ASCII characters are used in the password,
    which could lead to weak passwords being set for samba
    users, making it vulnerable to dictionary
    attacks.(CVE-2019-14833)

  - A flaw was found in samba 4.0.0 before samba 4.9.15 and
    samba 4.10.x before 4.10.10. An attacker can crash AD
    DC LDAP server via dirsync resulting in denial of
    service. Privilege escalation is not possible with this
    issue.(CVE-2019-14847)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2547
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bab6fc12");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14833");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10218");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/09");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libsmbclient-4.7.1-9.h13.eulerosv2r7",
        "libwbclient-4.7.1-9.h13.eulerosv2r7",
        "samba-4.7.1-9.h13.eulerosv2r7",
        "samba-client-4.7.1-9.h13.eulerosv2r7",
        "samba-client-libs-4.7.1-9.h13.eulerosv2r7",
        "samba-common-4.7.1-9.h13.eulerosv2r7",
        "samba-common-libs-4.7.1-9.h13.eulerosv2r7",
        "samba-common-tools-4.7.1-9.h13.eulerosv2r7",
        "samba-libs-4.7.1-9.h13.eulerosv2r7",
        "samba-python-4.7.1-9.h13.eulerosv2r7",
        "samba-winbind-4.7.1-9.h13.eulerosv2r7",
        "samba-winbind-clients-4.7.1-9.h13.eulerosv2r7",
        "samba-winbind-modules-4.7.1-9.h13.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
