#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175202);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/07");

  script_cve_id(
    "CVE-2019-8921",
    "CVE-2022-0204",
    "CVE-2022-39176",
    "CVE-2022-39177"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.0 : bluez (EulerOS-SA-2023-1742)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bluez package installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - An issue was discovered in bluetoothd in BlueZ through 5.48. The vulnerability lies in the handling of a
    SVC_ATTR_REQ by the SDP implementation. By crafting a malicious CSTATE, it is possible to trick the server
    into returning more bytes than the buffer actually holds, resulting in leaking arbitrary heap data. The
    root cause can be found in the function service_attr_req of sdpd-request.c. The server does not check
    whether the CSTATE data is the same in consecutive requests, and instead simply trusts that it is the
    same. (CVE-2019-8921)

  - A heap overflow vulnerability was found in bluez in versions prior to 5.63. An attacker with local network
    access could pass specially crafted files causing an application to halt or crash, leading to a denial of
    service. (CVE-2022-0204)

  - BlueZ before 5.59 allows physically proximate attackers to obtain sensitive information because
    profiles/audio/avrcp.c does not validate params_len. (CVE-2022-39176)

  - BlueZ before 5.59 allows physically proximate attackers to cause a denial of service because malformed and
    invalid capabilities can be processed in profiles/audio/avdtp.c. (CVE-2022-39177)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1742
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?870cc483");
  script_set_attribute(attribute:"solution", value:
"Update the affected bluez packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0204");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39177");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bluez-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "bluez-libs-5.44-4.h8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez");
}
