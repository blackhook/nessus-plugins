#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1979-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130408);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id(
    "CVE-2014-6051",
    "CVE-2014-6052",
    "CVE-2014-6053",
    "CVE-2014-6054",
    "CVE-2014-6055",
    "CVE-2016-9941",
    "CVE-2016-9942",
    "CVE-2018-15126",
    "CVE-2018-15127",
    "CVE-2018-20019",
    "CVE-2018-20020",
    "CVE-2018-20021",
    "CVE-2018-20022",
    "CVE-2018-20023",
    "CVE-2018-20024",
    "CVE-2018-20748",
    "CVE-2018-20749",
    "CVE-2018-20750",
    "CVE-2018-6307",
    "CVE-2018-7225",
    "CVE-2019-15681"
  );
  script_bugtraq_id(70091, 70092, 70093, 70094, 70096);
  script_xref(name:"IAVA", value:"2020-A-0381");

  script_name(english:"Debian DLA-1979-1 : italc security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been identified in the VNC code of iTALC,
a classroom management software. All vulnerabilities referenced below
are issues that have originally been reported against Debian source
package libvncserver. The italc source package in Debian ships a
custom-patched version of libvncserver, thus libvncserver's security
fixes required porting over.

CVE-2014-6051

Integer overflow in the MallocFrameBuffer function in vncviewer.c in
LibVNCServer allowed remote VNC servers to cause a denial of service
(crash) and possibly executed arbitrary code via an advertisement for
a large screen size, which triggered a heap-based buffer overflow.

CVE-2014-6052

The HandleRFBServerMessage function in libvncclient/rfbproto.c in
LibVNCServer did not check certain malloc return values, which allowed
remote VNC servers to cause a denial of service (application crash) or
possibly execute arbitrary code by specifying a large screen size in a
(1) FramebufferUpdate, (2) ResizeFrameBuffer, or (3)
PalmVNCReSizeFrameBuffer message.

CVE-2014-6053

The rfbProcessClientNormalMessage function in libvncserver/rfbserver.c
in LibVNCServer did not properly handle attempts to send a large
amount of ClientCutText data, which allowed remote attackers to cause
a denial of service (memory consumption or daemon crash) via a crafted
message that was processed by using a single unchecked malloc.

CVE-2014-6054

The rfbProcessClientNormalMessage function in libvncserver/rfbserver.c
in LibVNCServer allowed remote attackers to cause a denial of service
(divide-by-zero error and server crash) via a zero value in the
scaling factor in a (1) PalmVNCSetScaleFactor or (2) SetScale message.

CVE-2014-6055

Multiple stack-based buffer overflows in the File Transfer feature in
rfbserver.c in LibVNCServer allowed remote authenticated users to
cause a denial of service (crash) and possibly execute arbitrary code
via a (1) long file or (2) directory name or the (3) FileTime
attribute in a rfbFileTransferOffer message.

CVE-2016-9941

Heap-based buffer overflow in rfbproto.c in LibVNCClient in
LibVNCServer allowed remote servers to cause a denial of service
(application crash) or possibly execute arbitrary code via a crafted
FramebufferUpdate message containing a subrectangle outside of the
client drawing area.

CVE-2016-9942

Heap-based buffer overflow in ultra.c in LibVNCClient in LibVNCServer
allowed remote servers to cause a denial of service (application
crash) or possibly execute arbitrary code via a crafted
FramebufferUpdate message with the Ultra type tile, such that the LZO
payload decompressed length exceeded what is specified by the tile
dimensions.

CVE-2018-6307

LibVNC contained heap use-after-free vulnerability in server code of
file transfer extension that can result remote code execution.

CVE-2018-7225

An issue was discovered in LibVNCServer.
rfbProcessClientNormalMessage() in rfbserver.c did not sanitize
msg.cct.length, leading to access to uninitialized and potentially
sensitive data or possibly unspecified other impact (e.g., an integer
overflow) via specially crafted VNC packets.

CVE-2018-15126

LibVNC contained heap use-after-free vulnerability in server code of
file transfer extension that can result remote code execution.

CVE-2018-15127

LibVNC contained heap out-of-bound write vulnerability in server code
of file transfer extension that can result remote code execution

CVE-2018-20749

LibVNC contained a heap out-of-bounds write vulnerability in
libvncserver/rfbserver.c. The fix for CVE-2018-15127 was incomplete.

CVE-2018-20750

LibVNC contained a heap out-of-bounds write vulnerability in
libvncserver/rfbserver.c. The fix for CVE-2018-15127 was incomplete.

CVE-2018-20019

LibVNC contained multiple heap out-of-bound write vulnerabilities in
VNC client code that can result remote code execution

CVE-2018-20748

LibVNC contained multiple heap out-of-bounds write vulnerabilities in
libvncclient/rfbproto.c. The fix for CVE-2018-20019 was incomplete.

CVE-2018-20020

LibVNC contained heap out-of-bound write vulnerability inside
structure in VNC client code that can result remote code execution

CVE-2018-20021

LibVNC contained a CWE-835: Infinite loop vulnerability in VNC client
code. Vulnerability allows attacker to consume excessive amount of
resources like CPU and RAM

CVE-2018-20022

LibVNC contained multiple weaknesses CWE-665: Improper Initialization
vulnerability in VNC client code that allowed attackers to read stack
memory and could be abused for information disclosure. Combined with
another vulnerability, it could be used to leak stack memory layout
and in bypassing ASLR.

CVE-2018-20023

LibVNC contained CWE-665: Improper Initialization vulnerability in VNC
Repeater client code that allowed attacker to read stack memory and
could be abused for information disclosure. Combined with another
vulnerability, it could be used to leak stack memory layout and in
bypassing ASLR.

CVE-2018-20024

LibVNC contained NULL pointer dereference in VNC client code that
could result DoS.

CVE-2019-15681

LibVNC contained a memory leak (CWE-655) in VNC server code, which
allowed an attacker to read stack memory and could be abused for
information disclosure. Combined with another vulnerability, it could
be used to leak stack memory and bypass ASLR. This attack appeared to
be exploitable via network connectivity.

For Debian 8 'Jessie', these problems have been fixed in version
1:2.0.2+dfsg1-2+deb8u1.

We recommend that you upgrade your italc packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2019/10/msg00042.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/italc");
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7225");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:italc-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:italc-client-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:italc-management-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:italc-management-console-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:italc-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:italc-master-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libitalccore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libitalccore-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"8.0", prefix:"italc-client", reference:"1:2.0.2+dfsg1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"italc-client-dbg", reference:"1:2.0.2+dfsg1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"italc-management-console", reference:"1:2.0.2+dfsg1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"italc-management-console-dbg", reference:"1:2.0.2+dfsg1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"italc-master", reference:"1:2.0.2+dfsg1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"italc-master-dbg", reference:"1:2.0.2+dfsg1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libitalccore", reference:"1:2.0.2+dfsg1-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libitalccore-dbg", reference:"1:2.0.2+dfsg1-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
