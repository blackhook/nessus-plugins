#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0018. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174069);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/11");

  script_cve_id(
    "CVE-2018-15518",
    "CVE-2018-19869",
    "CVE-2018-19870",
    "CVE-2018-19871",
    "CVE-2018-19873"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : qt5-qtdoc Multiple Vulnerabilities (NS-SA-2023-0018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has qt5-qtdoc packages installed that are affected
by multiple vulnerabilities:

  - QXmlStream in Qt 5.x before 5.11.3 has a double-free or corruption during parsing of a specially crafted
    illegal XML document. (CVE-2018-15518)

  - An issue was discovered in Qt before 5.11.3. A malformed SVG image causes a segmentation fault in
    qsvghandler.cpp. (CVE-2018-19869)

  - An issue was discovered in Qt before 5.11.3. A malformed GIF image causes a NULL pointer dereference in
    QGifHandler resulting in a segmentation fault. (CVE-2018-19870)

  - An issue was discovered in Qt before 5.11.3. There is QTgaFile Uncontrolled Resource Consumption.
    (CVE-2018-19871)

  - An issue was discovered in Qt before 5.11.3. QBmpHandler has a buffer overflow via BMP data.
    (CVE-2018-19873)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0018");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-15518");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-19869");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-19870");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-19871");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-19873");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL qt5-qtdoc packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:qt5-qtdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qt5-qtdoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.05" &&
    os_release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'qt5-qtdoc-5.9.7-1.el7'
  ],
  'CGSL MAIN 5.05': [
    'qt5-qtdoc-5.9.7-1.el7'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qt5-qtdoc');
}
