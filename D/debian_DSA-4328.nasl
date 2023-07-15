#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4328. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118474);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/02");

  script_cve_id("CVE-2018-14665");
  script_xref(name:"DSA", value:"4328");
  script_xref(name:"IAVB", value:"2018-B-0140");

  script_name(english:"Debian DSA-4328-1 : xorg-server - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Narendra Shinde discovered that incorrect command-line parameter
validation in the Xorg X server may result in arbitary file overwrite,
which can result in privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/xorg-server"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4328"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the xorg-server packages.

For the stable distribution (stretch), this problem has been fixed in
version 2:1.19.2-1+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14665");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Xorg X11 Server SUID modulepath Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"xdmx", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xdmx-tools", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xnest", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xorg-server-source", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-common", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xephyr", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xorg-core", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xorg-core-udeb", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xorg-dev", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xserver-xorg-legacy", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xvfb", reference:"2:1.19.2-1+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"xwayland", reference:"2:1.19.2-1+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
