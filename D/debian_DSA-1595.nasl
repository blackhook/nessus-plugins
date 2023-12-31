#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1595. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33176);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
  script_bugtraq_id(29665, 29666, 29668, 29669, 29670);
  script_xref(name:"DSA", value:"1595");

  script_name(english:"Debian DSA-1595-1 : xorg-server - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local vulnerabilities have been discovered in the X Window
system. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2008-1377
    Lack of validation of the parameters of the
    SProcSecurityGenerateAuthorization and
    SProcRecordCreateContext functions makes it possible for
    a specially crafted request to trigger the swapping of
    bytes outside the parameter of these requests, causing
    memory corruption.

  - CVE-2008-1379
    An integer overflow in the validation of the parameters
    of the ShmPutImage() request makes it possible to
    trigger the copy of arbitrary server memory to a pixmap
    that can subsequently be read by the client, to read
    arbitrary parts of the X server memory space.

  - CVE-2008-2360
    An integer overflow may occur in the computation of the
    size of the glyph to be allocated by the AllocateGlyph()
    function which will cause less memory to be allocated
    than expected, leading to later heap overflow.

  - CVE-2008-2361
    An integer overflow may occur in the computation of the
    size of the glyph to be allocated by the
    ProcRenderCreateCursor() function which will cause less
    memory to be allocated than expected, leading later to
    dereferencing un-mapped memory, causing a crash of the X
    server.

  - CVE-2008-2362
    Integer overflows can also occur in the code validating
    the parameters for the SProcRenderCreateLinearGradient,
    SProcRenderCreateRadialGradient and
    SProcRenderCreateConicalGradient functions, leading to
    memory corruption by swapping bytes outside of the
    intended request parameters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2008/dsa-1595"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xorg-server package.

For the stable distribution (etch), these problems have been fixed in
version 2:1.1.1-21etch5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"4.0", prefix:"xdmx", reference:"2:1.1.1-21etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xdmx-tools", reference:"2:1.1.1-21etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xnest", reference:"2:1.1.1-21etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xserver-xephyr", reference:"2:1.1.1-21etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xserver-xorg-core", reference:"2:1.1.1-21etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xserver-xorg-dev", reference:"2:1.1.1-21etch5")) flag++;
if (deb_check(release:"4.0", prefix:"xvfb", reference:"2:1.1.1-21etch5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
