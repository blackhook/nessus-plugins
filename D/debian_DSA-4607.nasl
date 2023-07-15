#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4607. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133110);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2019-16239");
  script_xref(name:"DSA", value:"4607");

  script_name(english:"Debian DSA-4607-1 : openconnect - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Lukas Kupczyk reported a vulnerability in the handling of chunked HTTP
in openconnect, an open client for Cisco AnyConnect, Pulse and
GlobalProtect VPN. A malicious HTTP server (after having accepted its
identity certificate), can provide bogus chunk lengths for chunked
HTTP encoding and cause a heap-based buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=940871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openconnect"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openconnect"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/openconnect"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4607"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openconnect packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 7.08-1+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 8.02-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openconnect");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
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
if (deb_check(release:"10.0", prefix:"libopenconnect-dev", reference:"8.02-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libopenconnect5", reference:"8.02-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"openconnect", reference:"8.02-1+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libopenconnect-dev", reference:"7.08-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libopenconnect5", reference:"7.08-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libopenconnect5-dbg", reference:"7.08-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openconnect", reference:"7.08-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"openconnect-dbg", reference:"7.08-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
