#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3426. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(175966);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_cve_id(
    "CVE-2021-31439",
    "CVE-2022-0194",
    "CVE-2022-23121",
    "CVE-2022-23122",
    "CVE-2022-23123",
    "CVE-2022-23124",
    "CVE-2022-23125",
    "CVE-2022-43634",
    "CVE-2022-45188"
  );

  script_name(english:"Debian DLA-3426-1 : netatalk - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3426 advisory.

  - This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations
    of Synology DiskStation Manager. Authentication is not required to exploit this vulnerablity. The specific
    flaw exists within the processing of DSI structures in Netatalk. The issue results from the lack of proper
    validation of the length of user-supplied data prior to copying it to a heap-based buffer. An attacker can
    leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-12326.
    (CVE-2021-31439)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the ad_addcomment function. The issue results from the lack of proper validation of the length of user-
    supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this
    vulnerability to execute code in the context of root. Was ZDI-CAN-15876. (CVE-2022-0194)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the parse_entries function. The issue results from the lack of proper error handling when parsing
    AppleDouble entries. An attacker can leverage this vulnerability to execute code in the context of root.
    Was ZDI-CAN-15819. (CVE-2022-23121)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the setfilparams function. The issue results from the lack of proper validation of the length of user-
    supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this
    vulnerability to execute code in the context of root. Was ZDI-CAN-15837. (CVE-2022-23122)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the getdirparams method. The issue results from the lack of proper validation of user-supplied data, which
    can result in a read past the end of an allocated buffer. An attacker can leverage this in conjunction
    with other vulnerabilities to execute arbitrary code in the context of root. Was ZDI-CAN-15830.
    (CVE-2022-23123)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the get_finderinfo method. The issue results from the lack of proper validation of user-supplied data,
    which can result in a read past the end of an allocated buffer. An attacker can leverage this in
    conjunction with other vulnerabilities to execute arbitrary code in the context of root. Was ZDI-
    CAN-15870. (CVE-2022-23124)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the copyapplfile function. When parsing the len element, the process does not properly validate the length
    of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage
    this vulnerability to execute code in the context of root. Was ZDI-CAN-15869. (CVE-2022-23125)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of
    Netatalk. Authentication is not required to exploit this vulnerability. The specific flaw exists within
    the dsi_writeinit function. The issue results from the lack of proper validation of the length of user-
    supplied data prior to copying it to a fixed-length heap-based buffer. An attacker can leverage this
    vulnerability to execute code in the context of root. Was ZDI-CAN-17646. (CVE-2022-43634)

  - Netatalk through 3.1.13 has an afp_getappl heap-based buffer overflow resulting in code execution via a
    crafted .appl file. This provides remote root access on some platforms such as FreeBSD (used for TrueNAS).
    (CVE-2022-45188)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1034170");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/netatalk");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3426");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31439");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23121");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23122");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23123");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23124");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23125");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43634");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45188");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/netatalk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the netatalk packages.

For Debian 10 buster, these problems have been fixed in version 3.1.12~ds-3+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31439");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-43634");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:netatalk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:netatalk-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'netatalk', 'reference': '3.1.12~ds-3+deb10u1'},
    {'release': '10.0', 'prefix': 'netatalk-dbg', 'reference': '3.1.12~ds-3+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'netatalk / netatalk-dbg');
}
