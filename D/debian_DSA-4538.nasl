#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4538. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129416);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/23");

  script_cve_id("CVE-2019-13377", "CVE-2019-16275");
  script_xref(name:"DSA", value:"4538");

  script_name(english:"Debian DSA-4538-1 : wpa - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were found in the WPA protocol implementation
found in wpa_supplication (station) and hostapd (access point).

  - CVE-2019-13377
    A timing-based side-channel attack against WPA3's
    Dragonfly handshake when using Brainpool curves could be
    used by an attacker to retrieve the password.

  - CVE-2019-16275
    Insufficient source address validation for some received
    Management frames in hostapd could lead to a denial of
    service for stations associated to an access point. An
    attacker in radio range of the access point could inject
    a specially constructed unauthenticated IEEE 802.11
    frame to the access point to cause associated stations
    to be disconnected and require a reconnection to the
    network."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=934180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=940080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-16275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/wpa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/wpa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4538"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wpa packages.

For the stable distribution (buster), these problems have been fixed
in version 2:2.7+git20190128+0c1e29f-6+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13377");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"hostapd", reference:"2:2.7+git20190128+0c1e29f-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"wpagui", reference:"2:2.7+git20190128+0c1e29f-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"wpasupplicant", reference:"2:2.7+git20190128+0c1e29f-6+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"wpasupplicant-udeb", reference:"2:2.7+git20190128+0c1e29f-6+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
