#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-142. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14979);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2002-0391");
  script_bugtraq_id(5356);
  script_xref(name:"CERT", value:"192995");
  script_xref(name:"DSA", value:"142");

  script_name(english:"Debian DSA-142-1 : openafs - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow bug has been discovered in the RPC library used by
the OpenAFS database server, which is derived from the SunRPC library.
This bug could be exploited to crash certain OpenAFS servers
(volserver, vlserver, ptserver, buserver) or to obtain unauthorized
root access to a host running one of these processes. No exploits are
known to exist yet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-142"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openafs packages.

This problem has been fixed in version 1.2.3final2-6 for the current
stable distribution (woody) and in version 1.2.6-1 for the unstable
distribution (sid). Debian 2.2 (potato) is not affected since it
doesn't contain OpenAFS packages.

OpenAFS is only available for the architectures alpha, i386, powerpc,
s390, sparc. Hence, we only provide fixed packages for these
architectures."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openafs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libopenafs-dev", reference:"1.2.3final2-6")) flag++;
if (deb_check(release:"3.0", prefix:"openafs-client", reference:"1.2.3final2-6")) flag++;
if (deb_check(release:"3.0", prefix:"openafs-dbserver", reference:"1.2.3final2-6")) flag++;
if (deb_check(release:"3.0", prefix:"openafs-fileserver", reference:"1.2.3final2-6")) flag++;
if (deb_check(release:"3.0", prefix:"openafs-kpasswd", reference:"1.2.3final2-6")) flag++;
if (deb_check(release:"3.0", prefix:"openafs-modules-source", reference:"1.2.3final2-6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
