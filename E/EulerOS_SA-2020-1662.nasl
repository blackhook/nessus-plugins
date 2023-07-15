#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137504);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2019-18634", "CVE-2019-19232", "CVE-2019-19234");

  script_name(english:"EulerOS 2.0 SP2 : sudo (EulerOS-SA-2020-1662)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the sudo package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - ** DISPUTED ** In Sudo through 1.8.29, an attacker with
    access to a Runas ALL sudoer account can impersonate a
    nonexistent user by invoking sudo with a numeric uid
    that is not associated with any user. NOTE: The
    software maintainer believes that this is not a
    vulnerability because running a command via sudo as a
    user not present in the local password database is an
    intentional feature. Because this behavior surprised
    some users, sudo 1.8.30 introduced an option to
    enable/disable this behavior with the default being
    disabled. However, this does not change the fact that
    sudo was behaving as intended, and as documented, in
    earlier versions.(CVE-2019-19232)

  - ** DISPUTED ** In Sudo through 1.8.29, the fact that a
    user has been blocked (e.g., by using the ! character
    in the shadow file instead of a password hash) is not
    considered, allowing an attacker (who has access to a
    Runas ALL sudoer account) to impersonate any blocked
    user. NOTE: The software maintainer believes that this
    CVE is not valid. Disabling local password
    authentication for a user is not the same as disabling
    all access to that user--the user may still be able to
    login via other means (ssh key, kerberos, etc). Both
    the Linux shadow(5) and passwd(1) manuals are clear on
    this. Indeed it is a valid use case to have local
    accounts that are _only_ accessible via sudo and that
    cannot be logged into with a password. Sudo 1.8.30
    added an optional setting to check the _shell_ of the
    target user (not the encrypted password!) against the
    contents of /etc/shells but that is not the same thing
    as preventing access to users with an invalid password
    hash.(CVE-2019-19234)

  - In Sudo before 1.8.26, if pwfeedback is enabled in
    /etc/sudoers, users can trigger a stack-based buffer
    overflow in the privileged sudo process. (pwfeedback is
    a default setting in Linux Mint and elementary OS
    however, it is NOT the default for upstream and many
    other packages, and would exist only if enabled by an
    administrator.) The attacker needs to deliver a long
    string to the stdin of getln() in
    tgetpass.c.(CVE-2019-18634)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1662
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfd468a9");
  script_set_attribute(attribute:"solution", value:
"Update the affected sudo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19234");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-18634");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["sudo-1.8.6p7-23.h8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");
}
