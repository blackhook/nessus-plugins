#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157941);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/12");

  script_cve_id("CVE-2021-3468");

  script_name(english:"EulerOS Virtualization 3.0.6.0 : avahi (EulerOS-SA-2022-1055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the avahi packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in avahi in versions 0.6 up to 0.8. The event used to signal the termination of the
    client connection on the avahi Unix socket is not correctly handled in the client_work function, allowing
    a local attacker to trigger an infinite loop. The highest threat from this vulnerability is to the
    availability of the avahi service, which becomes unresponsive after this flaw is triggered.
    (CVE-2021-3468)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1055
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cec45801");
  script_set_attribute(attribute:"solution", value:
"Update the affected avahi packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:avahi-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:avahi-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:avahi-ui-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "avahi-0.7-16.h8.eulerosv2r8",
  "avahi-autoipd-0.7-16.h8.eulerosv2r8",
  "avahi-devel-0.7-16.h8.eulerosv2r8",
  "avahi-glib-0.7-16.h8.eulerosv2r8",
  "avahi-gobject-0.7-16.h8.eulerosv2r8",
  "avahi-libs-0.7-16.h8.eulerosv2r8",
  "avahi-ui-gtk3-0.7-16.h8.eulerosv2r8",
  "python2-avahi-0.7-16.h8.eulerosv2r8",
  "python3-avahi-0.7-16.h8.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi");
}
