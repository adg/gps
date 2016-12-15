package gps

import (
	"bytes"
	"crypto/sha256"
	"sort"
)

// HashInputs computes a hash digest of all data in SolveParams and the
// RootManifest that act as function inputs to Solve().
//
// The digest returned from this function is the same as the digest that would
// be included with a Solve() Result. As such, it's appropriate for comparison
// against the digest stored in a lock file, generated by a previous Solve(): if
// the digests match, then manifest and lock are in sync, and a Solve() is
// unnecessary.
//
// (Basically, this is for memoization.)
func (s *solver) HashInputs() []byte {
	// Apply overrides to the constraints from the root. Otherwise, the hash
	// would be computed on the basis of a constraint from root that doesn't
	// actually affect solving.
	p := s.ovr.overrideAll(s.rm.DependencyConstraints().merge(s.rm.TestDependencyConstraints()))

	// Build up a buffer of all the inputs.
	buf := new(bytes.Buffer)
	for _, pd := range p {
		buf.WriteString(string(pd.Ident.ProjectRoot))
		buf.WriteString(pd.Ident.NetworkName)
		// FIXME Constraint.String() is a surjective-only transformation - tags
		// and branches with the same name are written out as the same string.
		// This could, albeit rarely, result in input collisions when a real
		// change has occurred.
		buf.WriteString(pd.Constraint.String())
	}

	// Write each of the packages, or the errors that were found for a
	// particular subpath, into the hash.
	for _, perr := range s.rpt.Packages {
		if perr.Err != nil {
			buf.WriteString(perr.Err.Error())
		} else {
			buf.WriteString(perr.P.Name)
			buf.WriteString(perr.P.CommentPath)
			buf.WriteString(perr.P.ImportPath)
			for _, imp := range perr.P.Imports {
				buf.WriteString(imp)
			}
			for _, imp := range perr.P.TestImports {
				buf.WriteString(imp)
			}
		}
	}

	// Add the package ignores, if any.
	if len(s.ig) > 0 {
		// Dump and sort the ignores
		ig := make([]string, len(s.ig))
		k := 0
		for pkg := range s.ig {
			ig[k] = pkg
			k++
		}
		sort.Strings(ig)

		for _, igp := range ig {
			buf.WriteString(igp)
		}
	}

	for _, pc := range s.ovr.asSortedSlice() {
		buf.WriteString(string(pc.Ident.ProjectRoot))
		if pc.Ident.NetworkName != "" {
			buf.WriteString(pc.Ident.NetworkName)
		}
		if pc.Constraint != nil {
			buf.WriteString(pc.Constraint.String())
		}
	}

	an, av := s.b.AnalyzerInfo()
	buf.WriteString(an)
	buf.WriteString(av.String())

	hd := sha256.Sum256(buf.Bytes())
	return hd[:]
}
