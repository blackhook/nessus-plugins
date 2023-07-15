#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144734);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2017-0381", "CVE-2017-7555");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : augeas (EulerOS-SA-2021-1042)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the augeas package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The Opus codec is designed for interactive speech and
    audio transmission over the Internet. It is designed by
    the IETF Codec Working Group and incorporates
    technology from Skype's SILK codec and Xiph.Org's CELT
    codec.Security Fix(es):An information disclosure
    vulnerability in silk/NLSF_stabilize.c in libopus in
    Mediaserver could enable a local malicious application
    to access data outside of its permission levels. This
    issue is rated as Moderate because it could be used to
    access sensitive data without permission. Product:
    Android. Versions: 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.
    Android ID: A-31607432.(CVE-2017-0381)Augeas versions
    up to and including 1.8.0 are vulnerable to heap-based
    buffer overflow due to improper handling of escaped
    strings. Attacker could send crafted strings that would
    cause the application using augeas to copy past the end
    of a buffer, leading to a crash or possible code
    execution.(CVE-2017-7555)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1042
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4514f3d");
  script_set_attribute(attribute:"solution", value:
"Update the affected augeas packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0381");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7555");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:augeas-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["augeas-libs-1.4.0-5.3"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "augeas");
}
