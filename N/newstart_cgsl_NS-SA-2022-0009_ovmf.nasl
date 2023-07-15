##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0009. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160735);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2017-5731",
    "CVE-2017-5732",
    "CVE-2017-5733",
    "CVE-2017-5734",
    "CVE-2017-5735",
    "CVE-2018-3613",
    "CVE-2018-5407",
    "CVE-2018-12181",
    "CVE-2019-0160",
    "CVE-2019-0161"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : ovmf Multiple Vulnerabilities (NS-SA-2022-0009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has ovmf packages installed that are affected by
multiple vulnerabilities:

  - Bounds checking in Tianocompress before November 7, 2017 may allow an authenticated user to potentially
    enable an escalation of privilege via local access. (CVE-2017-5731)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was in a CNA pool
    that was not assigned to any issues during 2017. Notes: none. (CVE-2017-5732, CVE-2017-5733,
    CVE-2017-5735)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by
    its CNA. Notes: none. (CVE-2017-5734)

  - Stack overflow in corrupted bmp for EDK II may allow unprivileged user to potentially enable denial of
    service or elevation of privilege via local access. (CVE-2018-12181)

  - Logic issue in variable service module for EDK II/UDK2018/UDK2017/UDK2015 may allow an authenticated user
    to potentially enable escalation of privilege, information disclosure and/or denial of service via local
    access. (CVE-2018-3613)

  - Simultaneous Multi-threading (SMT) in processors can enable local users to exploit software vulnerable to
    timing attacks via a side-channel timing attack on 'port contention'. (CVE-2018-5407)

  - Buffer overflow in system firmware for EDK II may allow unauthenticated user to potentially enable
    escalation of privilege and/or denial of service via network access. (CVE-2019-0160)

  - Stack overflow in XHCI for EDK II may allow an unauthenticated user to potentially enable denial of
    service via local access. (CVE-2019-0161)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0009");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-5731");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-5732");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-5733");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-5734");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-5735");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-12181");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-3613");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-5407");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-0160");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-0161");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ovmf packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:OVMF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:OVMF");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'OVMF-20180508-6.gitee3198e672e2.el7.cgslv5_4.0.1.g7d971ab'
  ],
  'CGSL MAIN 5.04': [
    'OVMF-20180508-6.gitee3198e672e2.el7.cgslv5_4.0.1.g7d971ab'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ovmf');
}
