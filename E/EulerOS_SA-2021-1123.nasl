#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145109);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/22");

  script_cve_id(
    "CVE-2020-15049",
    "CVE-2020-15810",
    "CVE-2020-15811"
  );

  script_name(english:"EulerOS 2.0 SP3 : squid (EulerOS-SA-2021-1123)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the squid packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in
    http/ContentLengthInterpreter.cc in Squid before 4.12
    and 5.x before 5.0.3. A Request Smuggling and Poisoning
    attack can succeed against the HTTP cache. The client
    sends an HTTP request with a Content-Length header
    containing '+\ '-' or an uncommon shell whitespace
    character prefix to the length
    field-value.(CVE-2020-15049)

  - An issue was discovered in Squid before 4.13 and 5.x
    before 5.0.4. Due to incorrect data validation, HTTP
    Request Smuggling attacks may succeed against HTTP and
    HTTPS traffic. This leads to cache poisoning. This
    allows any client, including browser scripts, to bypass
    local security and poison the proxy cache and any
    downstream caches with content from an arbitrary
    source. When configured for relaxed header parsing (the
    default), Squid relays headers containing whitespace
    characters to upstream servers. When this occurs as a
    prefix to a Content-Length header, the frame length
    specified will be ignored by Squid (allowing for a
    conflicting length to be used from another
    Content-Length header) but relayed
    upstream.(CVE-2020-15810)

  - An issue was discovered in Squid before 4.13 and 5.x
    before 5.0.4. Due to incorrect data validation, HTTP
    Request Splitting attacks may succeed against HTTP and
    HTTPS traffic. This leads to cache poisoning. This
    allows any client, including browser scripts, to bypass
    local security and poison the browser cache and any
    downstream caches with content from an arbitrary
    source. Squid uses a string search instead of parsing
    the Transfer-Encoding header to find chunked encoding.
    This allows an attacker to hide a second request inside
    Transfer-Encoding: it is interpreted by Squid as
    chunked and split out into a second request delivered
    upstream. Squid will then deliver two distinct
    responses to the client, corrupting any downstream
    caches.(CVE-2020-15811)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e19be93c");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["squid-3.5.20-2.2.h9",
        "squid-migration-script-3.5.20-2.2.h9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
