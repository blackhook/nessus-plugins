#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2356-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140055);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/24");

  script_cve_id("CVE-2014-0791", "CVE-2020-11042", "CVE-2020-11045", "CVE-2020-11046", "CVE-2020-11048", "CVE-2020-11058", "CVE-2020-11521", "CVE-2020-11522", "CVE-2020-11523", "CVE-2020-11525", "CVE-2020-11526", "CVE-2020-13396", "CVE-2020-13397", "CVE-2020-13398");
  script_bugtraq_id(64689);

  script_name(english:"Debian DLA-2356-1 : freerdp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilites have been reported against FreeRDP, an Open
Source server and client implementation of the Microsoft RDP protocol.

CVE-2014-0791

An integer overflow in the license_read_scope_list function in
libfreerdp/core/license.c in FreeRDP allowed remote RDP servers to
cause a denial of service (application crash) or possibly have
unspecified other impact via a large ScopeCount value in a Scope List
in a Server License Request packet.

CVE-2020-11042

In FreeRDP there was an out-of-bounds read in update_read_icon_info.
It allowed reading an attacker-defined amount of client memory (32bit
unsigned -> 4GB) to an intermediate buffer. This could have been used
to crash the client or store information for later retrieval.

CVE-2020-11045

In FreeRDP there was an out-of-bound read in in
update_read_bitmap_data that allowed client memory to be read to an
image buffer. The result displayed on screen as colour.

CVE-2020-11046

In FreeRDP there was a stream out-of-bounds seek in
update_read_synchronize that could have lead to a later out-of-bounds
read.

CVE-2020-11048

In FreeRDP there was an out-of-bounds read. It only allowed to abort a
session. No data extraction was possible.

CVE-2020-11058

In FreeRDP, a stream out-of-bounds seek in
rdp_read_font_capability_set could have lead to a later out-of-bounds
read. As a result, a manipulated client or server might have forced a
disconnect due to an invalid data read.

CVE-2020-11521

libfreerdp/codec/planar.c in FreeRDP had an Out-of-bounds Write.

CVE-2020-11522

libfreerdp/gdi/gdi.c in FreeRDP had an Out-of-bounds Read.

CVE-2020-11523

libfreerdp/gdi/region.c in FreeRDP had an Integer Overflow.

CVE-2020-11525

libfreerdp/cache/bitmap.c in FreeRDP had an Out of bounds read.

CVE-2020-11526

libfreerdp/core/update.c in FreeRDP had an Out-of-bounds Read.

CVE-2020-13396

An out-of-bounds (OOB) read vulnerability has been detected in
ntlm_read_ChallengeMessage in winpr/libwinpr/sspi/NTLM/ntlm_message.c.

CVE-2020-13397

An out-of-bounds (OOB) read vulnerability has been detected in
security_fips_decrypt in libfreerdp/core/security.c due to an
uninitialized value.

CVE-2020-13398

An out-of-bounds (OOB) write vulnerability has been detected in
crypto_rsa_common in libfreerdp/crypto/crypto.c.

For Debian 9 stretch, these problems have been fixed in version
1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4.

We recommend that you upgrade your freerdp packages.

For the detailed security status of freerdp please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/freerdp

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/freerdp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/freerdp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0791");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp-x11-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-cache1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-client1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-codec1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-common1.1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-core1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-crypto1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-gdi1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-locale1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-plugins-standard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-plugins-standard-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-primitives1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-rail1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-utils1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-asn1-0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-bcrypt0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-credentials0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-credui0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-crt0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-crypto0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-dsparse0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-environment0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-error0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-file0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-handle0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-heap0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-input0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-interlocked0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-io0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-library0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-path0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-pipe0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-pool0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-registry0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-rpc0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-sspi0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-sspicli0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-synch0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-sysinfo0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-thread0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-timezone0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-utils0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-winhttp0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-winsock0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxfreerdp-client-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxfreerdp-client1.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"freerdp-x11", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"freerdp-x11-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-cache1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-client1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-codec1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-common1.1.0", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-core1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-crypto1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-dev", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-gdi1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-locale1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-plugins-standard", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-plugins-standard-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-primitives1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-rail1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libfreerdp-utils1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-asn1-0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-bcrypt0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-credentials0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-credui0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-crt0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-crypto0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-dev", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-dsparse0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-environment0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-error0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-file0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-handle0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-heap0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-input0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-interlocked0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-io0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-library0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-path0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-pipe0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-pool0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-registry0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-rpc0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-sspi0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-sspicli0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-synch0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-sysinfo0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-thread0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-timezone0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-utils0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-winhttp0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libwinpr-winsock0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libxfreerdp-client-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libxfreerdp-client1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
