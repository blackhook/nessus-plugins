#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2969. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159473);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/03");

  script_cve_id(
    "CVE-2019-13161",
    "CVE-2019-18610",
    "CVE-2019-18790",
    "CVE-2019-18976",
    "CVE-2020-28242"
  );

  script_name(english:"Debian DLA-2969-1 : asterisk - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2969 advisory.

  - An issue was discovered in Asterisk Open Source through 13.27.0, 14.x and 15.x through 15.7.2, and 16.x
    through 16.4.0, and Certified Asterisk through 13.21-cert3. A pointer dereference in chan_sip while
    handling SDP negotiation allows an attacker to crash Asterisk when handling an SDP answer to an outgoing
    T.38 re-invite. To exploit this vulnerability an attacker must cause the chan_sip module to send a T.38
    re-invite request to them. Upon receipt, the attacker must send an SDP answer containing both a T.38 UDPTL
    stream and another media stream containing only a codec (which is not permitted according to the chan_sip
    configuration). (CVE-2019-13161)

  - An issue was discovered in manager.c in Sangoma Asterisk through 13.x, 16.x, 17.x and Certified Asterisk
    13.21 through 13.21-cert4. A remote authenticated Asterisk Manager Interface (AMI) user without system
    authorization could use a specially crafted Originate AMI request to execute arbitrary system commands.
    (CVE-2019-18610)

  - An issue was discovered in channels/chan_sip.c in Sangoma Asterisk 13.x before 13.29.2, 16.x before
    16.6.2, and 17.x before 17.0.1, and Certified Asterisk 13.21 before cert5. A SIP request can be sent to
    Asterisk that can change a SIP peer's IP address. A REGISTER does not need to occur, and calls can be
    hijacked as a result. The only thing that needs to be known is the peer's name; authentication details
    such as passwords do not need to be known. This vulnerability is only exploitable when the nat option is
    set to the default, or auto_force_rport. (CVE-2019-18790)

  - An issue was discovered in res_pjsip_t38.c in Sangoma Asterisk through 13.x and Certified Asterisk through
    13.21-x. If it receives a re-invite initiating T.38 faxing and has a port of 0 and no c line in the SDP, a
    NULL pointer dereference and crash will occur. This is different from CVE-2019-18940. (CVE-2019-18976)

  - An issue was discovered in Asterisk Open Source 13.x before 13.37.1, 16.x before 16.14.1, 17.x before
    17.8.1, and 18.x before 18.0.1 and Certified Asterisk before 16.8-cert5. If Asterisk is challenged on an
    outbound INVITE and the nonce is changed in each response, Asterisk will continually send INVITEs in a
    loop. This causes Asterisk to consume more and more memory since the transaction will never terminate
    (even if the call is hung up), ultimately leading to a restart or shutdown of Asterisk. Outbound
    authentication must be configured on the endpoint for this to occur. (CVE-2020-28242)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/asterisk");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2969");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13161");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18610");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18790");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18976");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28242");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/asterisk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the asterisk packages.

For Debian 9 stretch, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dahdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-ooh323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-imapstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-odbcstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-vpb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'asterisk', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-config', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-dahdi', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-dev', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-doc', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-mobile', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-modules', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-mp3', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-mysql', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-ooh323', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-voicemail', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-voicemail-imapstorage', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-voicemail-odbcstorage', 'reference': '1:13.14.1~dfsg-2+deb9u6'},
    {'release': '9.0', 'prefix': 'asterisk-vpb', 'reference': '1:13.14.1~dfsg-2+deb9u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'asterisk / asterisk-config / asterisk-dahdi / asterisk-dev / etc');
}
