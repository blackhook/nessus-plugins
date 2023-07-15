#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103004);
  script_version("3.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id(
    "CVE-2014-3694",
    "CVE-2014-3696",
    "CVE-2014-3698",
    "CVE-2017-2640"
  );
  script_bugtraq_id(
    70701,
    70703,
    70705
  );

  script_name(english:"EulerOS 2.0 SP2 : pidgin (EulerOS-SA-2017-1166)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the pidgin package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A denial of service flaw was found in the way Pidgin's
    Mxit plug-in handled emoticons. A malicious remote
    server or a man-in-the-middle attacker could
    potentially use this flaw to crash Pidgin by sending a
    specially crafted emoticon. (CVE-2014-3695)

  - A denial of service flaw was found in the way Pidgin
    parsed Groupwise server messages. A malicious remote
    server or a man-in-the-middle attacker could
    potentially use this flaw to cause Pidgin to consume an
    excessive amount of memory, possibly leading to a
    crash, by sending a specially crafted message.
    (CVE-2014-3696)

  - An information disclosure flaw was discovered in the
    way Pidgin parsed XMPP messages. A malicious remote
    server or a man-in-the-middle attacker could
    potentially use this flaw to disclose a portion of
    memory belonging to the Pidgin process by sending a
    specially crafted XMPP message. (CVE-2014-3698)

  - An out-of-bounds write flaw was found in the way Pidgin
    processed XML content. A malicious remote server could
    potentially use this flaw to crash Pidgin or execute
    arbitrary code in the context of the pidgin process.
    (CVE-2017-2640)

  - It was found that Pidgin's SSL/TLS plug-ins had a flaw
    in the certificate validation functionality. An
    attacker could use this flaw to create a fake
    certificate, that Pidgin would trust, which could be
    used to conduct man-in-the-middle attacks against
    Pidgin. (CVE-2014-3694)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1166
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43f84ebc");
  script_set_attribute(attribute:"solution", value:
"Update the affected pidgin packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libpurple");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["libpurple-2.10.11-5"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pidgin");
}
