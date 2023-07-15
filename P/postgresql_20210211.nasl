#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# Portions Copyright (C) 1996-2019, The PostgreSQL Global Development Group
# Portions Copyright (C) 1994, The Regents of the University of California
# Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee, and without a written agreement is hereby granted, provided that the above copyright notice and this paragraph and the following two paragraphs appear in all copies.
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148419);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2021-3393", "CVE-2021-20229");
  script_xref(name:"IAVB", value:"2021-B-0023-S");

  script_name(english:"PostgreSQL 11.x < 11.11 / 12.x < 12.6 / 13.x < 13.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 11 prior to 11.11, 12 prior to 12.6, or 13 prior to 13.2. As
such, it is potentially affected by multiple vulnerabilities :

  - An information leak was discovered in postgresql in versions before 13.2, before 12.6 and before 11.11.
    A user having UPDATE permission but not SELECT permission to a particular column could craft queries
    which, under some circumstances, might disclose values from that column in error messages. An attacker
    could use this flaw to obtain information stored in a column they are allowed to write but not read.
    (CVE-2021-3393)

  - A flaw was found in PostgreSQL in versions before 13.2, before 12.6, before 11.11. This flaw allows a
    user with SELECT privilege on one column to craft a special query that returns all columns of the table.
    The highest threat from this vulnerability is to confidentiality (CVE-2021-20229)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-132-126-1111-1016-9621-and-9525-released-2165/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56673af4");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-20229");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3393");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 11.11 / 12.6 / 13.2 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20229");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgres_installed_windows.nbin", "postgres_installed_nix.nbin", "postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432, "installed_sw/PostgreSQL");

  exit(0);
}

include('vcf_extras_postgresql.inc');

var app = 'PostgreSQL';
var win_local = TRUE;

if (!get_kb_item('SMB/Registry/Enumerated'))
  win_local = FALSE;

var port = get_service(svc:'postgresql', default:5432);
var kb_base = 'database/' + port + '/postgresql/';
var kb_ver = NULL;
var kb_path = kb_base + 'version';
var ver = get_kb_item(kb_path);
if (!empty_or_null(ver)) kb_ver = kb_path;

app_info = vcf::postgresql::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_base:kb_base, win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:2);

#  11.11 / 12.6 / 13.2
var constraints = [
  { 'min_version' : '11', 'fixed_version' : '11.11' },
  { 'min_version' : '12', 'fixed_version' : '12.6' },
  { 'min_version' : '13', 'fixed_version' : '13.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
