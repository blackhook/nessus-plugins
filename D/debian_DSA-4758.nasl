#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4758. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140299);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/17");

  script_cve_id("CVE-2020-14345", "CVE-2020-14346", "CVE-2020-14347", "CVE-2020-14361", "CVE-2020-14362");
  script_xref(name:"DSA", value:"4758");

  script_name(english:"Debian DSA-4758-1 : xorg-server - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the X.Org X server.
Missing input sanitising in X server extensions may result in local
privilege escalation if the X server is configured to run with root
privileges. In addition an ASLR bypass was fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=968986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4758"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the xorg-server packages.

For the stable distribution (buster), these problems have been fixed
in version 2:1.20.4-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14362");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");
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
if (deb_check(release:"10.0", prefix:"xdmx", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xdmx-tools", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xnest", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xorg-server-source", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xserver-common", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xserver-xephyr", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xserver-xorg-core", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xserver-xorg-core-udeb", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xserver-xorg-dev", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xserver-xorg-legacy", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xvfb", reference:"2:1.20.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"xwayland", reference:"2:1.20.4-1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
