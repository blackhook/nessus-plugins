#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1666-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122066);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789");

  script_name(english:"Debian DLA-1666-1 : freerdp security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"For the FreeRDP version in Debian jessie LTS a security and
functionality update has recently been provided. FreeRDP is a free
re-implementation of the Microsoft RDP protocol (server and client
side) with freerdp-x11 being the most common RDP client these days.

Functional improvements :

With help from FreeRDP upstream (cudos to Bernhard Miklautz and Martin
Fleisz) we are happy to announce that RDP proto v6 and CredSSP v3
support have been backported to the old FreeRDP 1.1 branch.

Since Q2/2018, Microsoft Windows servers and clients
received an update that defaulted their RDP server to proto
version 6. Since this change, people have not been able
anymore to connect to recently updated MS Windows machines
using old the FreeRDP 1.1 branch as found in Debian jessie
LTS and Debian stretch.

With the recent FreeRDP upload to Debian jessie LTS,
connecting to up-to-date MS Windows machines is now again
possible.

Security issues :

CVE-2018-8786

FreeRDP contained an integer truncation that lead to a heap-based
buffer overflow in function update_read_bitmap_update() and resulted
in a memory corruption and probably even a remote code execution.

CVE-2018-8787

FreeRDP contained an integer overflow that leads to a heap-based
buffer overflow in function gdi_Bitmap_Decompress() and resulted in a
memory corruption and probably even a remote code execution.

CVE-2018-8788

FreeRDP contained an out-of-bounds write of up to 4 bytes in function
nsc_rle_decode() that resulted in a memory corruption and possibly
even a remote code execution.

CVE-2018-8789

FreeRDP contained several out-of-bounds reads in the NTLM
authentication module that resulted in a denial of service (segfault).

For Debian 8 'Jessie', these security problems have been fixed in
version 1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3.

We recommend that you upgrade your freerdp packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/freerdp"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"freerdp-x11", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"freerdp-x11-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-cache1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-client1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-codec1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-common1.1.0", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-core1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-crypto1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-dev", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-gdi1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-locale1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-plugins-standard", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-plugins-standard-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-primitives1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-rail1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libfreerdp-utils1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-asn1-0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-bcrypt0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-credentials0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-credui0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-crt0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-crypto0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-dev", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-dsparse0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-environment0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-error0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-file0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-handle0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-heap0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-input0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-interlocked0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-io0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-library0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-path0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-pipe0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-pool0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-registry0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-rpc0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-sspi0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-sspicli0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-synch0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-sysinfo0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-thread0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-timezone0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-utils0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-winhttp0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libwinpr-winsock0.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libxfreerdp-client-dbg", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libxfreerdp-client1.1", reference:"1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
