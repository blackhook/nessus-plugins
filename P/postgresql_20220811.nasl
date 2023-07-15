#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# Portions Copyright (C) 1996-2019, The PostgreSQL Global Development Group
# Portions Copyright (C) 1994, The Regents of the University of California
# Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee, and without a written agreement is hereby granted, provided that the above copyright notice and this paragraph and the following two paragraphs appear in all copies.
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
##

include('compat.inc');

if (description)
{
  script_id(164433);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2022-2625");
  script_xref(name:"IAVB", value:"2022-B-0028-S");

  script_name(english:"PostgreSQL 10.x < 10.22 / 11.x < 11.17 / 12.x < 12.12 / 13.x < 13.8 / 14.x < 14.5 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 10 prior to 10.22, 11 prior to 11.17, 12 prior to 12.12, 13
prior to 13.8, or 14 prior to 14.5. As such, it is potentially affected by a vulnerability :
  - A vulnerability exists in postgresql. On this security issue an attack requires permission to create non-temporary 
objects in at least one schema, ability to lure or wait for an administrator to create or update an affected extension 
in that schema, and ability to lure or wait for a victim to use the object targeted in CREATE OR REPLACE or CREATE IF 
NOT EXISTS. Given all three prerequisites, the attacker can run arbitrary code as the victim role, which may be a 
superuser. Known-affected extensions include both PostgreSQL-bundled and non-bundled extensions. PostgreSQL blocks this 
attack in the core server, so there's no need to modify individual extensions. (CVE-2022-2625)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-145-138-1212-1117-1022-and-15-beta-3-released-2496/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09235872");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2625");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 10.22 / 11.17 / 12.12 / 13.8 / 14.5 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('backport.inc');

var port = get_service(svc:'postgresql', default:5432, exit_on_fail:TRUE);
var kb_base = 'database/' + port + '/postgresql/';

var kb_ver = kb_base + 'version';
get_kb_item_or_exit(kb_ver);

var kb_backport = NULL;
var source = get_kb_item_or_exit(kb_base + 'source');
get_backport_banner(banner:source);
if (backported) kb_backport = kb_base + 'backported';

var app_info = vcf::get_app_info(app:'PostgreSQL', port:port, kb_ver:kb_ver, kb_backport:kb_backport, service:TRUE);

#  10.22 / 11.17 / 12.12 / 13.8 / 14.5
var constraints = [
  { 'min_version' : '10', 'fixed_version' : '10.22' },
  { 'min_version' : '11', 'fixed_version' : '11.17' },
  { 'min_version' : '12', 'fixed_version' : '12.12' },
  { 'min_version' : '13', 'fixed_version' : '13.8' },
  { 'min_version' : '14', 'fixed_version' : '14.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
