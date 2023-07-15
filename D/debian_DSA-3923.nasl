#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3923. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102097);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839");
  script_xref(name:"DSA", value:"3923");

  script_name(english:"Debian DSA-3923-1 : freerdp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tyler Bohan of Talos discovered that FreeRDP, a free implementation of
the Remote Desktop Protocol (RDP), contained several vulnerabilities
that allowed a malicious remote server or a man-in-the-middle to
either cause a DoS by forcibly terminating the client, or execute
arbitrary code on the client side."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/freerdp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/freerdp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3923"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the freerdp packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1.

For the stable distribution (stretch), these problems have been fixed
in version 1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"freerdp-x11", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"freerdp-x11-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-cache1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-client1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-codec1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-common1.1.0", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-core1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-crypto1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-dev", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-gdi1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-locale1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-plugins-standard", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-plugins-standard-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-primitives1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-rail1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-utils1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-asn1-0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-bcrypt0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-credentials0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-credui0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-crt0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-crypto0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-dev", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-dsparse0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-environment0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-error0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-file0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-handle0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-heap0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-input0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-interlocked0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-io0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-library0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-path0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-pipe0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-pool0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-registry0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-rpc0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-sspi0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-sspicli0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-synch0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-sysinfo0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-thread0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-timezone0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-utils0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-winhttp0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-winsock0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxfreerdp-client-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxfreerdp-client1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"freerdp-x11", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"freerdp-x11-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-cache1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-client1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-codec1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-common1.1.0", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-core1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-crypto1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-dev", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-gdi1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-locale1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-plugins-standard", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-plugins-standard-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-primitives1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-rail1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-utils1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-asn1-0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-bcrypt0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-credentials0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-credui0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-crt0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-crypto0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-dev", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-dsparse0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-environment0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-error0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-file0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-handle0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-heap0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-input0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-interlocked0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-io0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-library0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-path0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-pipe0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-pool0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-registry0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-rpc0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-sspi0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-sspicli0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-synch0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-sysinfo0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-thread0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-timezone0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-utils0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-winhttp0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-winsock0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxfreerdp-client-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxfreerdp-client1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
