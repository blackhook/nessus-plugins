#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4023. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104442);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-15566");
  script_xref(name:"DSA", value:"4023");

  script_name(english:"Debian DSA-4023-1 : slurm-llnl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ryan Day discovered that the Simple Linux Utility for Resource
Management (SLURM), a cluster resource management and job scheduling
system, does not properly handle SPANK environment variables, allowing
a user permitted to submit jobs to execute code as root during the
Prolog or Epilog. All systems using a Prolog or Epilog script are
vulnerable, regardless of whether SPANK plugins are in use."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=880530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/slurm-llnl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4023"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the slurm-llnl packages.

For the stable distribution (stretch), this problem has been fixed in
version 16.05.9-1+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-llnl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libpam-slurm", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi0", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi0-dbg", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi0-dev", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi2-0", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi2-0-dbg", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi2-0-dev", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libslurm-dev", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libslurm-perl", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libslurm30", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libslurm30-dbg", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libslurmdb-dev", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libslurmdb-perl", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libslurmdb30", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libslurmdb30-dbg", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-client", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-client-dbg", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-client-emulator", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-llnl", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-llnl-slurmdbd", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-basic-plugins", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-basic-plugins-dbg", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-basic-plugins-dev", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-doc", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-emulator", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-torque", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurmctld", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurmctld-dbg", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurmd", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurmd-dbg", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurmdbd", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"slurmdbd-dbg", reference:"16.05.9-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"sview", reference:"16.05.9-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
