#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131630);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-10965",
    "CVE-2017-10966",
    "CVE-2017-5193",
    "CVE-2017-5194",
    "CVE-2017-5356",
    "CVE-2017-9468",
    "CVE-2017-9469",
    "CVE-2018-5205",
    "CVE-2018-5206",
    "CVE-2018-5207",
    "CVE-2018-5208"
  );

  script_name(english:"EulerOS 2.0 SP2 : irssi (EulerOS-SA-2019-2477)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the irssi package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - In Irssi before 1.0.6, a calculation error in the
    completion code could cause a heap buffer overflow when
    completing certain strings.(CVE-2018-5208)

  - When using incomplete escape codes, Irssi before 1.0.6
    may access data beyond the end of the
    string.(CVE-2018-5205)

  - When the channel topic is set without specifying a
    sender, Irssi before 1.0.6 may dereference a NULL
    pointer.(CVE-2018-5206)

  - When using an incomplete variable argument, Irssi
    before 1.0.6 may access data beyond the end of the
    string.(CVE-2018-5207)

  - The nickcmp function in Irssi before 0.8.21 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and crash) via a message without a
    nick.(CVE-2017-5193)

  - Use-after-free vulnerability in Irssi before 0.8.21
    allows remote attackers to cause a denial of service
    (crash) via an invalid nick message.(CVE-2017-5194)

  - Irssi before 0.8.21 allows remote attackers to cause a
    denial of service (out-of-bounds read and crash) via a
    string containing a formatting sequence (%[) without a
    closing bracket (]).(CVE-2017-5356)

  - In Irssi before 1.0.3, when receiving a DCC message
    without source nick/host, it attempts to dereference a
    NULL pointer. Thus, remote IRC servers can cause a
    crash.(CVE-2017-9468)

  - In Irssi before 1.0.3, when receiving certain
    incorrectly quoted DCC files, it tries to find the
    terminating quote one byte before the allocated memory.
    Thus, remote attackers might be able to cause a
    crash.(CVE-2017-9469)

  - An issue was discovered in Irssi before 1.0.4. When
    receiving messages with invalid time stamps, Irssi
    would try to dereference a NULL
    pointer.(CVE-2017-10965)

  - An issue was discovered in Irssi before 1.0.4. While
    updating the internal nick list, Irssi could
    incorrectly use the GHashTable interface and free the
    nick while updating it. This would then result in
    use-after-free conditions on each access of the hash
    table.(CVE-2017-10966)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2477
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a565e87c");
  script_set_attribute(attribute:"solution", value:
"Update the affected irssi packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:irssi");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["irssi-0.8.15-16.h6"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irssi");
}
