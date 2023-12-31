#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2508. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60088);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-0217");
  script_bugtraq_id(53856);
  script_xref(name:"DSA", value:"2508");

  script_name(english:"Debian DSA-2508-1 : kfreebsd-8 - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Rafal Wojtczuk from Bromium discovered that FreeBSD wasn't handling
correctly uncanonical return addresses on Intel amd64 CPUs, allowing
privilege escalation to kernel for local users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=677297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/kfreebsd-8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2012/dsa-2508"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kfreebsd-8 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 8.1+dfsg-8+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'FreeBSD Intel SYSRET Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kfreebsd-8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8-486", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8-686", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8-686-smp", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8-amd64", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1-486", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1-686", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1-686-smp", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-headers-8.1-1-amd64", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8-486", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8-686", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8-686-smp", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8-amd64", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8.1-1-486", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8.1-1-686", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8.1-1-686-smp", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-image-8.1-1-amd64", reference:"8.1+dfsg-8+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"kfreebsd-source-8.1", reference:"8.1+dfsg-8+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
