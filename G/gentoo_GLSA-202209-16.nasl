#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202209-16.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(165542);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/29");

  script_cve_id(
    "CVE-2020-26558",
    "CVE-2021-0129",
    "CVE-2021-3588",
    "CVE-2022-0204"
  );

  script_name(english:"GLSA-202209-16 : BlueZ: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202209-16 (BlueZ: Multiple Vulnerabilities)

  - Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby
    man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication
    procedure) by reflection of the public key and the authentication evidence of the initiating device,
    potentially permitting this attacker to complete authenticated pairing with the responding device using
    the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit
    at a time. (CVE-2020-26558)

  - Improper access control in BlueZ may allow an authenticated user to potentially enable information
    disclosure via adjacent access. (CVE-2021-0129)

  - The cli_feat_read_cb() function in src/gatt-database.c does not perform bounds checks on the 'offset'
    variable before using it as an index into an array for reading. (CVE-2021-3588)

  - A heap overflow vulnerability was found in bluez in versions prior to 5.63. An attacker with local network
    access could pass specially crafted files causing an application to halt or crash, leading to a denial of
    service. (CVE-2022-0204)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202209-16");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=797712");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835077");
  script_set_attribute(attribute:"solution", value:
"All BlueZ users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-wireless/bluez-5.63");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bluez");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "net-wireless/bluez",
    'unaffected' : make_list("ge 5.63", "lt 5.0.0"),
    'vulnerable' : make_list("lt 5.63")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BlueZ");
}
