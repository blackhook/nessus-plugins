##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0058. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143938);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id("CVE-2017-6519");
  script_bugtraq_id(106782);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : avahi Vulnerability (NS-SA-2020-0058)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has avahi packages installed that are affected by
a vulnerability:

  - avahi-daemon in Avahi through 0.6.32 and 0.7 inadvertently responds to IPv6 unicast queries with source
    addresses that are not on-link, which allows remote attackers to cause a denial of service (traffic
    amplification) and may cause information leakage by obtaining potentially sensitive information from the
    responding device via port-5353 UDP packets. NOTE: this may overlap CVE-2015-2809. (CVE-2017-6519)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0058");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL avahi packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6519");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'avahi-0.6.31-20.el7',
    'avahi-autoipd-0.6.31-20.el7',
    'avahi-compat-howl-0.6.31-20.el7',
    'avahi-compat-howl-devel-0.6.31-20.el7',
    'avahi-compat-libdns_sd-0.6.31-20.el7',
    'avahi-compat-libdns_sd-devel-0.6.31-20.el7',
    'avahi-debuginfo-0.6.31-20.el7',
    'avahi-devel-0.6.31-20.el7',
    'avahi-dnsconfd-0.6.31-20.el7',
    'avahi-glib-0.6.31-20.el7',
    'avahi-glib-devel-0.6.31-20.el7',
    'avahi-gobject-0.6.31-20.el7',
    'avahi-gobject-devel-0.6.31-20.el7',
    'avahi-libs-0.6.31-20.el7',
    'avahi-qt3-0.6.31-20.el7',
    'avahi-qt3-devel-0.6.31-20.el7',
    'avahi-qt4-0.6.31-20.el7',
    'avahi-qt4-devel-0.6.31-20.el7',
    'avahi-tools-0.6.31-20.el7',
    'avahi-ui-0.6.31-20.el7',
    'avahi-ui-devel-0.6.31-20.el7',
    'avahi-ui-gtk3-0.6.31-20.el7',
    'avahi-ui-tools-0.6.31-20.el7'
  ],
  'CGSL MAIN 5.04': [
    'avahi-0.6.31-20.el7',
    'avahi-autoipd-0.6.31-20.el7',
    'avahi-compat-howl-0.6.31-20.el7',
    'avahi-compat-howl-devel-0.6.31-20.el7',
    'avahi-compat-libdns_sd-0.6.31-20.el7',
    'avahi-compat-libdns_sd-devel-0.6.31-20.el7',
    'avahi-debuginfo-0.6.31-20.el7',
    'avahi-devel-0.6.31-20.el7',
    'avahi-dnsconfd-0.6.31-20.el7',
    'avahi-glib-0.6.31-20.el7',
    'avahi-glib-devel-0.6.31-20.el7',
    'avahi-gobject-0.6.31-20.el7',
    'avahi-gobject-devel-0.6.31-20.el7',
    'avahi-libs-0.6.31-20.el7',
    'avahi-qt3-0.6.31-20.el7',
    'avahi-qt3-devel-0.6.31-20.el7',
    'avahi-qt4-0.6.31-20.el7',
    'avahi-qt4-devel-0.6.31-20.el7',
    'avahi-tools-0.6.31-20.el7',
    'avahi-ui-0.6.31-20.el7',
    'avahi-ui-devel-0.6.31-20.el7',
    'avahi-ui-gtk3-0.6.31-20.el7',
    'avahi-ui-tools-0.6.31-20.el7'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'avahi');
}
