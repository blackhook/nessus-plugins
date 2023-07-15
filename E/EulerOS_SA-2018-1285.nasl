#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117729);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-14495",
    "CVE-2017-14496"
  );

  script_name(english:"EulerOS 2.0 SP2 : dnsmasq (EulerOS-SA-2018-1285)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the dnsmasq packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A memory exhaustion flaw was found in dnsmasq in the
    EDNS0 code. An attacker could send crafted DNS packets
    which would trigger memory allocations which would
    never be freed, leading to unbounded memory consumption
    and eventually a crash. This issue only affected
    configurations using one of the options: add-mac,
    add-cpe-id, or add-subnet. (CVE-2017-14495)

  - An integer underflow flaw leading to a buffer over-read
    was found in dnsmasq in the EDNS0 code. An attacker
    could send crafted DNS packets to dnsmasq which would
    cause it to crash. This issue only affected
    configurations using one of the options: add-mac,
    add-cpe-id, or add-subnet. (CVE-2017-14496)

As this issue only affects configurations using the add-mac,
add-cpe-id, or add-subnet options, and these are not enabled by
default in dnsmasq on EulerOS, this vulnerability may not actively
affect the system at this time, but has the potential to do so if the
configuration changes. Updating the version of these packages is the
safest course of action.

Note that Tenable Network Security has extracted most of the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1285
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3549a782");
  script_set_attribute(attribute:"solution", value:
"Update the affected dnsmasq packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp", "Settings/ParanoidReport");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["dnsmasq-2.76-2.2",
        "dnsmasq-utils-2.76-2.2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dnsmasq");
}
