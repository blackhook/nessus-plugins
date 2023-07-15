#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5004. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155294);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2021-21341",
    "CVE-2021-21342",
    "CVE-2021-21343",
    "CVE-2021-21344",
    "CVE-2021-21345",
    "CVE-2021-21346",
    "CVE-2021-21347",
    "CVE-2021-21348",
    "CVE-2021-21349",
    "CVE-2021-21350",
    "CVE-2021-21351",
    "CVE-2021-29505",
    "CVE-2021-39139",
    "CVE-2021-39140",
    "CVE-2021-39141",
    "CVE-2021-39144",
    "CVE-2021-39145",
    "CVE-2021-39146",
    "CVE-2021-39147",
    "CVE-2021-39148",
    "CVE-2021-39149",
    "CVE-2021-39150",
    "CVE-2021-39151",
    "CVE-2021-39152",
    "CVE-2021-39153",
    "CVE-2021-39154"
  );
  script_xref(name:"CEA-ID", value:"CEA-2022-0035");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/31");

  script_name(english:"Debian DSA-5004-1 : libxstream-java - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5004 advisory.

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is vulnerability which may allow a remote attacker to allocate 100% CPU time on the target system
    depending on CPU type or parallel execution of such a payload resulting in a denial of service only by
    manipulating the processed input stream. No user is affected who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. If you rely on
    XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21341)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability where the processed stream at unmarshalling time contains type information to
    recreate the formerly written objects. XStream creates therefore new instances based on these type
    information. An attacker can manipulate the processed input stream and replace or inject objects, that
    result in a server-side forgery request. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. If you rely on
    XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21342)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability where the processed stream at unmarshalling time contains type information to
    recreate the formerly written objects. XStream creates therefore new instances based on these type
    information. An attacker can manipulate the processed input stream and replace or inject objects, that
    result in the deletion of a file on the local host. No user is affected, who followed the recommendation
    to setup XStream's security framework with a whitelist limited to the minimal required types. If you rely
    on XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21343)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to load and execute arbitrary code from a
    remote host only by manipulating the processed input stream. No user is affected, who followed the
    recommendation to setup XStream's security framework with a whitelist limited to the minimal required
    types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least
    version 1.4.16. (CVE-2021-21344, CVE-2021-21346, CVE-2021-21347)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker who has sufficient rights to execute commands
    of the host only by manipulating the processed input stream. No user is affected, who followed the
    recommendation to setup XStream's security framework with a whitelist limited to the minimal required
    types. If you rely on XStream's default blacklist of the Security Framework, you will have to use at least
    version 1.4.16. (CVE-2021-21345)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to occupy a thread that consumes maximum CPU
    time and will never return. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. If you rely on XStream's
    default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21348)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to request data from internal resources that
    are not publicly available only by manipulating the processed input stream. No user is affected, who
    followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal
    required types. If you rely on XStream's default blacklist of the Security Framework, you will have to use
    at least version 1.4.16. (CVE-2021-21349)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability which may allow a remote attacker to execute arbitrary code only by manipulating
    the processed input stream. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. If you rely on XStream's
    default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21350)

  - XStream is a Java library to serialize objects to XML and back again. In XStream before version 1.4.16,
    there is a vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host
    only by manipulating the processed input stream. No user is affected, who followed the recommendation to
    setup XStream's security framework with a whitelist limited to the minimal required types. If you rely on
    XStream's default blacklist of the Security Framework, you will have to use at least version 1.4.16.
    (CVE-2021-21351)

  - XStream is software for serializing Java objects to XML and back again. A vulnerability in XStream
    versions prior to 1.4.17 may allow a remote attacker has sufficient rights to execute commands of the host
    only by manipulating the processed input stream. No user who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types is affected. The
    vulnerability is patched in version 1.4.17. (CVE-2021-29505)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream. A user is only affected if using the version out of the box with
    JDK 1.7u21 or below. However, this scenario can be adjusted easily to an external Xalan that works
    regardless of the version of the Java runtime. No user is affected, who followed the recommendation to
    setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18
    uses no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39139)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU
    type or parallel execution of such a payload resulting in a denial of service only by manipulating the
    processed input stream. No user is affected, who followed the recommendation to setup XStream's security
    framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a
    blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39140)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses
    no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39141,
    CVE-2021-39145, CVE-2021-39146, CVE-2021-39147, CVE-2021-39148, CVE-2021-39149, CVE-2021-39151,
    CVE-2021-39154)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker has sufficient rights to execute commands of the host only by
    manipulating the processed input stream. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses
    no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39144)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to request data from internal resources that are not publicly
    available only by manipulating the processed input stream with a Java runtime version 14 to 8. No user is
    affected, who followed the recommendation to setup XStream's security framework with a whitelist limited
    to the minimal required types. If you rely on XStream's default blacklist of the [Security
    Framework](https://x-stream.github.io/security.html#framework), you will have to use at least version
    1.4.18. (CVE-2021-39150, CVE-2021-39152)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream, if using the version out of the box with Java runtime version 14
    to 8 or with JavaFX installed. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a
    blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39153)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/libxstream-java
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2068716");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5004");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21341");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21342");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21343");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21344");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21345");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21346");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21347");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21348");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21349");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21350");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21351");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-29505");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39139");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39140");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39141");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39144");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39145");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39146");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39147");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39148");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39149");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39150");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39151");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39152");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39154");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libxstream-java");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libxstream-java");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libxstream-java packages.

For the stable distribution (bullseye), these problems have been fixed in version 1.4.15-3+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21350");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21345");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware NSX Manager XStream unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxstream-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libxstream-java', 'reference': '1.4.11.1-1+deb10u3'},
    {'release': '11.0', 'prefix': 'libxstream-java', 'reference': '1.4.15-3+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxstream-java');
}
