#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-559-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92546);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-7974", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2516", "CVE-2016-2518");

  script_name(english:"Debian DLA-559-1 : ntp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the Network Time Protocol
daemon and utility programs :

CVE-2015-7974

Matt Street discovered that insufficient key validation allows
impersonation attacks between authenticated peers.

CVE-2015-7977 / CVE-2015-7978

Stephen Gray discovered that a NULL pointer dereference and a buffer
overflow in the handling of 'ntpdc reslist' commands may result in
denial of service.

CVE-2015-7979

Aanchal Malhotra discovered that if NTP is configured for broadcast
mode, an attacker can send malformed authentication packets which
break associations with the server for other broadcast clients.

CVE-2015-8138

Matthew van Gundy and Jonathan Gardner discovered that missing
validation of origin timestamps in ntpd clients may result in denial
of service.

CVE-2015-8158

Jonathan Gardner discovered that missing input sanitising in ntpq may
result in denial of service.

CVE-2016-1547

Stephen Gray and Matthew van Gundy discovered that incorrect handling
of crypto NAK packets my result in denial of service.

CVE-2016-1548

Jonathan Gardner and Miroslav Lichvar discovered that ntpd clients
could be forced to change from basic client/server mode to interleaved
symmetric mode, preventing time synchronisation.

CVE-2016-1550

Matthew van Gundy, Stephen Gray and Loganaden Velvindron discovered
that timing leaks in the the packet authentication code could result
in recovery of a message digest.

CVE-2016-2516

Yihan Lian discovered that duplicate IPs on 'unconfig' directives will
trigger an assert.

CVE-2016-2518

Yihan Lian discovered that an OOB memory access could potentially
crash ntpd.

For Debian 7 'Wheezy', these problems have been fixed in version
1:4.2.6.p5+dfsg-2+deb7u7.

We recommend that you upgrade your ntp packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/07/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ntp"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ntp, ntp-doc, and ntpdate packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"ntp", reference:"1:4.2.6.p5+dfsg-2+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"ntp-doc", reference:"1:4.2.6.p5+dfsg-2+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"ntpdate", reference:"1:4.2.6.p5+dfsg-2+deb7u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
