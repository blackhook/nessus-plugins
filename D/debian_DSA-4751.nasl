#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4751. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139929);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-15810", "CVE-2020-15811", "CVE-2020-24606");
  script_xref(name:"DSA", value:"4751");
  script_xref(name:"IAVB", value:"2020-B-0050-S");

  script_name(english:"Debian DSA-4751-1 : squid - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in Squid, a fully featured web
proxy cache, which could result in request splitting, request
smuggling (leading to cache poisoning) and denial of service when
processing crafted cache digest responses messages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=968932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=968933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=968934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/squid"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/squid"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4751"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the squid packages.

For the stable distribution (buster), these problems have been fixed
in version 4.6-1+deb10u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15811");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"squid", reference:"4.6-1+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"squid-cgi", reference:"4.6-1+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"squid-common", reference:"4.6-1+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"squid-purge", reference:"4.6-1+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"squid3", reference:"4.6-1+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"squidclient", reference:"4.6-1+deb10u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
