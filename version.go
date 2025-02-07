package gps

import (
	"sort"

	"github.com/Masterminds/semver"
)

// Version represents one of the different types of versions used by gps.
//
// Version composes Constraint, because all versions can be used as a constraint
// (where they allow one, and only one, version - themselves), but constraints
// are not necessarily discrete versions.
//
// Version is an interface, but it contains private methods, which restricts it
// to gps's own internal implementations. We do this for the confluence of
// two reasons: the implementation of Versions is complete (there is no case in
// which we'd need other types), and the implementation relies on type magic
// under the hood, which would be unsafe to do if other dynamic types could be
// hiding behind the interface.
type Version interface {
	Constraint

	// Indicates the type of version - Revision, Branch, Version, or Semver
	Type() string
}

// PairedVersion represents a normal Version, but paired with its corresponding,
// underlying Revision.
type PairedVersion interface {
	Version

	// Underlying returns the immutable Revision that identifies this Version.
	Underlying() Revision

	// Unpair returns the surface-level UnpairedVersion that half of the pair.
	//
	// It does NOT modify the original PairedVersion
	Unpair() UnpairedVersion

	// Ensures it is impossible to be both a PairedVersion and an
	// UnpairedVersion
	_pair(int)
}

// UnpairedVersion represents a normal Version, with a method for creating a
// VersionPair by indicating the version's corresponding, underlying Revision.
type UnpairedVersion interface {
	Version
	// Is takes the underlying Revision that this UnpairedVersion corresponds
	// to and unites them into a PairedVersion.
	Is(Revision) PairedVersion
	// Ensures it is impossible to be both a PairedVersion and an
	// UnpairedVersion
	_pair(bool)
}

// types are weird
func (branchVersion) _private()  {}
func (branchVersion) _pair(bool) {}
func (plainVersion) _private()   {}
func (plainVersion) _pair(bool)  {}
func (semVersion) _private()     {}
func (semVersion) _pair(bool)    {}
func (versionPair) _private()    {}
func (versionPair) _pair(int)    {}
func (Revision) _private()       {}

// NewBranch creates a new Version to represent a floating version (in
// general, a branch).
func NewBranch(body string) UnpairedVersion {
	return branchVersion{
		name: body,
		// We always set isDefault to false here, because the property is
		// specifically designed to be internal-only: only the SourceManager
		// gets to mark it. This is OK because nothing that client code is
		// responsible for needs to care about has to touch it it.
		//
		// TODO(sdboyer) ...maybe. this just ugly.
		isDefault: false,
	}
}

func newDefaultBranch(body string) UnpairedVersion {
	return branchVersion{
		name:      body,
		isDefault: true,
	}
}

// NewVersion creates a Semver-typed Version if the provided version string is
// valid semver, and a plain/non-semver version if not.
func NewVersion(body string) UnpairedVersion {
	sv, err := semver.NewVersion(body)

	if err != nil {
		return plainVersion(body)
	}
	return semVersion{sv: sv}
}

// A Revision represents an immutable versioning identifier.
type Revision string

// String converts the Revision back into a string.
func (r Revision) String() string {
	return string(r)
}

// Type indicates the type of version - for revisions, "revision".
func (r Revision) Type() string {
	return "revision"
}

// Matches is the Revision acting as a constraint; it checks to see if the provided
// version is the same Revision as itself.
func (r Revision) Matches(v Version) bool {
	switch tv := v.(type) {
	case versionTypeUnion:
		return tv.Matches(r)
	case Revision:
		return r == tv
	case versionPair:
		return r == tv.r
	}

	return false
}

// MatchesAny is the Revision acting as a constraint; it checks to see if the provided
// version is the same Revision as itself.
func (r Revision) MatchesAny(c Constraint) bool {
	switch tc := c.(type) {
	case anyConstraint:
		return true
	case noneConstraint:
		return false
	case versionTypeUnion:
		return tc.MatchesAny(r)
	case Revision:
		return r == tc
	case versionPair:
		return r == tc.r
	}

	return false
}

// Intersect computes the intersection of the Constraint with the provided
// Constraint. For Revisions, this can only be another, exactly equal
// Revision, or a PairedVersion whose underlying Revision is exactly equal.
func (r Revision) Intersect(c Constraint) Constraint {
	switch tc := c.(type) {
	case anyConstraint:
		return r
	case noneConstraint:
		return none
	case versionTypeUnion:
		return tc.Intersect(r)
	case Revision:
		if r == tc {
			return r
		}
	case versionPair:
		if r == tc.r {
			return r
		}
	}

	return none
}

type branchVersion struct {
	name      string
	isDefault bool
}

func (v branchVersion) String() string {
	return string(v.name)
}

func (v branchVersion) Type() string {
	return "branch"
}

func (v branchVersion) Matches(v2 Version) bool {
	switch tv := v2.(type) {
	case versionTypeUnion:
		return tv.Matches(v)
	case branchVersion:
		return v.name == tv.name
	case versionPair:
		if tv2, ok := tv.v.(branchVersion); ok {
			return tv2.name == v.name
		}
	}
	return false
}

func (v branchVersion) MatchesAny(c Constraint) bool {
	switch tc := c.(type) {
	case anyConstraint:
		return true
	case noneConstraint:
		return false
	case versionTypeUnion:
		return tc.MatchesAny(v)
	case branchVersion:
		return v.name == tc.name
	case versionPair:
		if tc2, ok := tc.v.(branchVersion); ok {
			return tc2.name == v.name
		}
	}

	return false
}

func (v branchVersion) Intersect(c Constraint) Constraint {
	switch tc := c.(type) {
	case anyConstraint:
		return v
	case noneConstraint:
		return none
	case versionTypeUnion:
		return tc.Intersect(v)
	case branchVersion:
		if v.name == tc.name {
			return v
		}
	case versionPair:
		if tc2, ok := tc.v.(branchVersion); ok {
			if v.name == tc2.name {
				return v
			}
		}
	}

	return none
}

func (v branchVersion) Is(r Revision) PairedVersion {
	return versionPair{
		v: v,
		r: r,
	}
}

type plainVersion string

func (v plainVersion) String() string {
	return string(v)
}

func (v plainVersion) Type() string {
	return "version"
}

func (v plainVersion) Matches(v2 Version) bool {
	switch tv := v2.(type) {
	case versionTypeUnion:
		return tv.Matches(v)
	case plainVersion:
		return v == tv
	case versionPair:
		if tv2, ok := tv.v.(plainVersion); ok {
			return tv2 == v
		}
	}
	return false
}

func (v plainVersion) MatchesAny(c Constraint) bool {
	switch tc := c.(type) {
	case anyConstraint:
		return true
	case noneConstraint:
		return false
	case versionTypeUnion:
		return tc.MatchesAny(v)
	case plainVersion:
		return v == tc
	case versionPair:
		if tc2, ok := tc.v.(plainVersion); ok {
			return tc2 == v
		}
	}

	return false
}

func (v plainVersion) Intersect(c Constraint) Constraint {
	switch tc := c.(type) {
	case anyConstraint:
		return v
	case noneConstraint:
		return none
	case versionTypeUnion:
		return tc.Intersect(v)
	case plainVersion:
		if v == tc {
			return v
		}
	case versionPair:
		if tc2, ok := tc.v.(plainVersion); ok {
			if v == tc2 {
				return v
			}
		}
	}

	return none
}

func (v plainVersion) Is(r Revision) PairedVersion {
	return versionPair{
		v: v,
		r: r,
	}
}

type semVersion struct {
	sv *semver.Version
}

func (v semVersion) String() string {
	str := v.sv.Original()
	if str == "" {
		str = v.sv.String()
	}
	return str
}

func (v semVersion) Type() string {
	return "semver"
}

func (v semVersion) Matches(v2 Version) bool {
	switch tv := v2.(type) {
	case versionTypeUnion:
		return tv.Matches(v)
	case semVersion:
		return v.sv.Equal(tv.sv)
	case versionPair:
		if tv2, ok := tv.v.(semVersion); ok {
			return tv2.sv.Equal(v.sv)
		}
	}
	return false
}

func (v semVersion) MatchesAny(c Constraint) bool {
	switch tc := c.(type) {
	case anyConstraint:
		return true
	case noneConstraint:
		return false
	case versionTypeUnion:
		return tc.MatchesAny(v)
	case semVersion:
		return v.sv.Equal(tc.sv)
	case semverConstraint:
		return tc.Intersect(v) != none
	case versionPair:
		if tc2, ok := tc.v.(semVersion); ok {
			return tc2.sv.Equal(v.sv)
		}
	}

	return false
}

func (v semVersion) Intersect(c Constraint) Constraint {
	switch tc := c.(type) {
	case anyConstraint:
		return v
	case noneConstraint:
		return none
	case versionTypeUnion:
		return tc.Intersect(v)
	case semVersion:
		if v.sv.Equal(tc.sv) {
			return v
		}
	case semverConstraint:
		return tc.Intersect(v)
	case versionPair:
		if tc2, ok := tc.v.(semVersion); ok {
			if v.sv.Equal(tc2.sv) {
				return v
			}
		}
	}

	return none
}

func (v semVersion) Is(r Revision) PairedVersion {
	return versionPair{
		v: v,
		r: r,
	}
}

type versionPair struct {
	v UnpairedVersion
	r Revision
}

func (v versionPair) String() string {
	return v.v.String()
}

func (v versionPair) Type() string {
	return v.v.Type()
}

func (v versionPair) Underlying() Revision {
	return v.r
}

func (v versionPair) Unpair() UnpairedVersion {
	return v.v
}

func (v versionPair) Matches(v2 Version) bool {
	switch tv2 := v2.(type) {
	case versionTypeUnion:
		return tv2.Matches(v)
	case versionPair:
		return v.r == tv2.r
	case Revision:
		return v.r == tv2
	}

	switch tv := v.v.(type) {
	case plainVersion, branchVersion:
		if tv.Matches(v2) {
			return true
		}
	case semVersion:
		if tv2, ok := v2.(semVersion); ok {
			if tv.sv.Equal(tv2.sv) {
				return true
			}
		}
	}

	return false
}

func (v versionPair) MatchesAny(c2 Constraint) bool {
	return c2.Matches(v)
}

func (v versionPair) Intersect(c2 Constraint) Constraint {
	switch tc := c2.(type) {
	case anyConstraint:
		return v
	case noneConstraint:
		return none
	case versionTypeUnion:
		return tc.Intersect(v)
	case versionPair:
		if v.r == tc.r {
			return v.r
		}
	case Revision:
		if v.r == tc {
			return v.r
		}
	case semverConstraint:
		if tv, ok := v.v.(semVersion); ok {
			if tc.Intersect(tv) == v.v {
				return v
			}
		}
		// If the semver intersection failed, we know nothing could work
		return none
	}

	switch tv := v.v.(type) {
	case plainVersion, branchVersion:
		if c2.Matches(v) {
			return v
		}
	case semVersion:
		if tv2, ok := c2.(semVersion); ok {
			if tv.sv.Equal(tv2.sv) {
				return v
			}
		}
	}

	return none
}

// compareVersionType is a sort func helper that makes a coarse-grained sorting
// decision based on version type.
//
// Make sure that l and r have already been converted from versionPair (if
// applicable).
func compareVersionType(l, r Version) int {
	// Big fugly double type switch. No reflect, because this can be smack in a hot loop
	switch l.(type) {
	case Revision:
		switch r.(type) {
		case Revision:
			return 0
		case branchVersion, plainVersion, semVersion:
			return 1
		}

	case plainVersion:
		switch r.(type) {
		case Revision:
			return -1
		case plainVersion:
			return 0
		case branchVersion, semVersion:
			return 1
		}

	case branchVersion:
		switch r.(type) {
		case Revision, plainVersion:
			return -1
		case branchVersion:
			return 0
		case semVersion:
			return 1
		}

	case semVersion:
		switch r.(type) {
		case Revision, branchVersion, plainVersion:
			return -1
		case semVersion:
			return 0
		}
	}
	panic("unknown version type")
}

// SortForUpgrade sorts a slice of []Version in roughly descending order, so
// that presumably newer versions are visited first. The rules are:
//
//  - All semver versions come first, and sort mostly according to the semver
//  2.0 spec (as implemented by github.com/Masterminds/semver lib), with one
//  exception:
//  - Semver versions with a prerelease are after *all* non-prerelease semver.
//  Within this subset they are sorted first by their numerical component, then
//  lexicographically by their prerelease version.
//  - The default branch(es) is next; the exact semantics of that are specific
//  to the underlying source.
//  - All other branches come next, sorted lexicographically.
//  - All non-semver versions (tags) are next, sorted lexicographically.
//  - Revisions, if any, are last, sorted lexicographically. Revisions do not
//  typically appear in version lists, so the only invariant we maintain is
//  determinism - deeper semantics, like chronology or topology, do not matter.
//
// So, given a slice of the following versions:
//
//  - Branch: master devel
//  - Semver tags: v1.0.0, v1.1.0, v1.1.0-alpha1
//  - Non-semver tags: footag
//  - Revision: f6e74e8d
//
// Sorting for upgrade will result in the following slice.
//
//  [v1.1.0 v1.0.0 v1.1.0-alpha1 footag devel master f6e74e8d]
func SortForUpgrade(vl []Version) {
	sort.Sort(upgradeVersionSorter(vl))
}

// SortForDowngrade sorts a slice of []Version in roughly ascending order, so
// that presumably older versions are visited first.
//
// This is *not* the same as reversing SortForUpgrade (or you could simply
// sort.Reverse()). The type precedence is the same, including the semver vs.
// semver-with-prerelease relation. Lexicographical comparisons within
// non-semver tags, branches, and revisions remains the same as well; because we
// treat these domains as having no ordering relation, there can be no real
// concept of "upgrade" vs "downgrade", so there is no reason to reverse them.
//
// Thus, the only binary relation that is reversed for downgrade is within-type
// comparisons for semver.
//
// So, given a slice of the following versions:
//
//  - Branch: master devel
//  - Semver tags: v1.0.0, v1.1.0, v1.1.0-alpha1
//  - Non-semver tags: footag
//  - Revision: f6e74e8d
//
// Sorting for downgrade will result in the following slice.
//
//  [v1.0.0 v1.1.0 v1.1.0-alpha1 footag devel master f6e74e8d]
func SortForDowngrade(vl []Version) {
	sort.Sort(downgradeVersionSorter(vl))
}

type upgradeVersionSorter []Version
type downgradeVersionSorter []Version

func (vs upgradeVersionSorter) Len() int {
	return len(vs)
}

func (vs upgradeVersionSorter) Swap(i, j int) {
	vs[i], vs[j] = vs[j], vs[i]
}

func (vs downgradeVersionSorter) Len() int {
	return len(vs)
}

func (vs downgradeVersionSorter) Swap(i, j int) {
	vs[i], vs[j] = vs[j], vs[i]
}

func (vs upgradeVersionSorter) Less(i, j int) bool {
	l, r := vs[i], vs[j]

	if tl, ispair := l.(versionPair); ispair {
		l = tl.v
	}
	if tr, ispair := r.(versionPair); ispair {
		r = tr.v
	}

	switch compareVersionType(l, r) {
	case -1:
		return true
	case 1:
		return false
	case 0:
		break
	default:
		panic("unreachable")
	}

	switch tl := l.(type) {
	case branchVersion:
		tr := r.(branchVersion)
		if tl.isDefault != tr.isDefault {
			// If they're not both defaults, then return the left val: if left
			// is the default, then it is "less" (true) b/c we want it earlier.
			// Else the right is the default, and so the left should be later
			// (false).
			return tl.isDefault
		}
		return l.String() < r.String()
	case Revision, plainVersion:
		// All that we can do now is alpha sort
		return l.String() < r.String()
	}

	// This ensures that pre-release versions are always sorted after ALL
	// full-release versions
	lsv, rsv := l.(semVersion).sv, r.(semVersion).sv
	lpre, rpre := lsv.Prerelease() == "", rsv.Prerelease() == ""
	if (lpre && !rpre) || (!lpre && rpre) {
		return lpre
	}
	return lsv.GreaterThan(rsv)
}

func (vs downgradeVersionSorter) Less(i, j int) bool {
	l, r := vs[i], vs[j]

	if tl, ispair := l.(versionPair); ispair {
		l = tl.v
	}
	if tr, ispair := r.(versionPair); ispair {
		r = tr.v
	}

	switch compareVersionType(l, r) {
	case -1:
		return true
	case 1:
		return false
	case 0:
		break
	default:
		panic("unreachable")
	}

	switch tl := l.(type) {
	case branchVersion:
		tr := r.(branchVersion)
		if tl.isDefault != tr.isDefault {
			// If they're not both defaults, then return the left val: if left
			// is the default, then it is "less" (true) b/c we want it earlier.
			// Else the right is the default, and so the left should be later
			// (false).
			return tl.isDefault
		}
		return l.String() < r.String()
	case Revision, plainVersion:
		// All that we can do now is alpha sort
		return l.String() < r.String()
	}

	// This ensures that pre-release versions are always sorted after ALL
	// full-release versions
	lsv, rsv := l.(semVersion).sv, r.(semVersion).sv
	lpre, rpre := lsv.Prerelease() == "", rsv.Prerelease() == ""
	if (lpre && !rpre) || (!lpre && rpre) {
		return lpre
	}
	return lsv.LessThan(rsv)
}
