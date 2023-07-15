#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0103. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127333);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2013-4075",
    "CVE-2015-3811",
    "CVE-2015-3812",
    "CVE-2015-3813"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : wireshark Multiple Vulnerabilities (NS-SA-2019-0103)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has wireshark packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in X11 dissector of wireshark of which
    an attacker could make wireshark consume excessive CPU
    resources which could make system unresponsive by
    injecting specially crafted packet onto the wire or by
    convincing wireshark user to read malformed packet trace
    file. (CVE-2015-3812)

  - A flaw was found in WCP dissector of wireshark of which
    an attacker could crash wireshark by injecting a
    specially crafted packet onto the wire or by convincing
    wireshark user to read malformed packet trace file.
    (CVE-2015-3811)

  - A flaw was found in the way packet reassembly code of
    wireshark would parse a packet which could leak memory.
    An attacker could use this flaw to crash wireshark by
    sending a specially crafted packet onto the wire or by
    convincing wireshark user to read malformed packet trace
    file. (CVE-2015-3813)

  - A flaw was found in GMR (Geo-Mobile Radio) 1 BCCH
    protocol dissector of wireshark which an attacker can
    trigger a denial of service attack and crash wireshark
    by sending a specially crafted packet onto the wire or
    by convincing wireshark user to read malformed packet
    trace file. (CVE-2013-4075)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0103");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL wireshark packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3812");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "wireshark-1.8.10-25.el6",
    "wireshark-gnome-1.8.10-25.el6"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
