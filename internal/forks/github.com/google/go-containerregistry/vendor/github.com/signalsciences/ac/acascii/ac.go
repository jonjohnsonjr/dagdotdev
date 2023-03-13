// Package ac provides an implementation of the Aho-Corasick string matching
// algorithm. Throughout this code []byte is referred to
// as a blice.
//
// http://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_string_matching_algorithm
//
// Copyright (c) 2013 CloudFlare, Inc.
//
// Originally from https://github.com/cloudflare/ahocorasick
package acascii

import (
	"container/list"
	"errors"
)

const maxchar = 128

// ErrNotASCII is returned when the dictionary input is not ASCII
var ErrNotASCII = errors.New("non-ASCII input")

// A node in the trie structure used to implement Aho-Corasick
type node struct {
	root bool // true if this is the root

	output bool // True means this node represents a blice that should
	// be output when matching

	b string // The path at this node

	index int // index into original dictionary if output is true

	counter int // Set to the value of the Matcher.counter when a
	// match is output to prevent duplicate output

	// The use of fixed size arrays is space-inefficient but fast for
	// lookups.

	child [maxchar]*node // A non-nil entry in this array means that the
	// index represents a byte value which can be
	// appended to the current node. Blices in the
	// trie are built up byte by byte through these
	// child node pointers.

	fails [maxchar]*node // Where to fail to (by following the fail
	// pointers) for each possible byte

	suffix *node // Pointer to the longest possible strict suffix of
	// this node

	fail *node // Pointer to the next node which is in the dictionary
	// which can be reached from here following suffixes. Called fail
	// because it is used to fallback in the trie when a match fails.
}

// Matcher contains a list of blices to match against
type Matcher struct {
	counter int // Counts the number of matches done, and is used to
	// prevent output of multiple matches of the same string
	trie []node // preallocated block of memory containing all the
	// nodes
	extent int   // offset into trie that is currently free
	root   *node // Points to trie[0]
}

// findBlice looks for a blice in the trie starting from the root and
// returns a pointer to the node representing the end of the blice. If
// the blice is not found it returns nil.
func (m *Matcher) findBlice(b string) *node {
	n := &m.trie[0]

	for n != nil && len(b) > 0 {
		n = n.child[int(b[0])]
		b = b[1:]
	}

	return n
}

// getFreeNode: gets a free node structure from the Matcher's trie
// pool and updates the extent to point to the next free node.
func (m *Matcher) getFreeNode() *node {
	m.extent++

	if m.extent == 1 {
		m.root = &m.trie[0]
		m.root.root = true
	}

	return &m.trie[m.extent-1]
}

// buildTrie builds the fundamental trie structure from a set of
// blices.
func (m *Matcher) buildTrie(dictionary [][]byte) error {

	// Work out the maximum size for the trie (all dictionary entries
	// are distinct plus the root). This is used to preallocate memory
	// for it.

	max := 1
	for _, blice := range dictionary {
		max += len(blice)
	}
	m.trie = make([]node, max)

	// Calling this an ignoring its argument simply allocated
	// m.trie[0] which will be the root element

	m.getFreeNode()

	// This loop builds the nodes in the trie by following through
	// each dictionary entry building the children pointers.

	for _, blice := range dictionary {
		n := m.root
		for i, b := range blice {
			idx := int(b)
			if idx >= maxchar {
				return ErrNotASCII 
			}
			c := n.child[idx]

			if c == nil {
				c = m.getFreeNode()
				n.child[idx] = c
				c.b = string(blice[0 : i+1])

				// Nodes directly under the root node will have the
				// root as their fail point as there are no suffixes
				// possible.

				if i == 0 {
					c.fail = m.root
				}

				c.suffix = m.root
			}

			n = c
		}

		// The last value of n points to the node representing a
		// dictionary entry

		n.output = true
		n.index = len(blice)
	}

	l := new(list.List)
	l.PushBack(m.root)

	for l.Len() > 0 {
		n := l.Remove(l.Front()).(*node)

		for i := 0; i < maxchar; i++ {
			c := n.child[i]
			if c != nil {
				l.PushBack(c)

				for j := 1; j < len(c.b); j++ {
					c.fail = m.findBlice(c.b[j:])
					if c.fail != nil {
						break
					}
				}

				if c.fail == nil {
					c.fail = m.root
				}

				for j := 1; j < len(c.b); j++ {
					s := m.findBlice(c.b[j:])
					if s != nil && s.output {
						c.suffix = s
						break
					}
				}
			}
		}
	}

	for i := 0; i < m.extent; i++ {
		for c := 0; c < maxchar; c++ {
			n := &m.trie[i]
			for n.child[c] == nil && !n.root {
				n = n.fail
			}

			m.trie[i].fails[c] = n
		}
	}

	m.trie = m.trie[:m.extent]
	return nil
}

// buildTrieString builds the fundamental trie structure from a []string
func (m *Matcher) buildTrieString(dictionary []string) error {

	// Work out the maximum size for the trie (all dictionary entries
	// are distinct plus the root). This is used to preallocate memory
	// for it.

	max := 1
	for _, blice := range dictionary {
		max += len(blice)

	}
	m.trie = make([]node, max)

	// Calling this an ignoring its argument simply allocated
	// m.trie[0] which will be the root element

	m.getFreeNode()

	// This loop builds the nodes in the trie by following through
	// each dictionary entry building the children pointers.

	for _, blice := range dictionary {
		n := m.root
		for i := 0; i < len(blice); i++ {
			index := int(blice[i])
			if index >= maxchar {
				return ErrNotASCII
			}
			b := int(blice[i])
			c := n.child[b]
			if c == nil {
				c = m.getFreeNode()
				n.child[b] = c
				c.b = blice[0 : i+1]

				// Nodes directly under the root node will have the
				// root as their fail point as there are no suffixes
				// possible.

				if i == 0 {
					c.fail = m.root
				}

				c.suffix = m.root
			}

			n = c
		}

		// The last value of n points to the node representing a
		// dictionary entry

		n.output = true
		n.index = len(blice)
	}

	l := new(list.List)
	l.PushBack(m.root)

	for l.Len() > 0 {
		n := l.Remove(l.Front()).(*node)

		for i := 0; i < maxchar; i++ {
			c := n.child[i]
			if c != nil {
				l.PushBack(c)

				for j := 1; j < len(c.b); j++ {
					c.fail = m.findBlice(c.b[j:])
					if c.fail != nil {
						break
					}
				}

				if c.fail == nil {
					c.fail = m.root
				}

				for j := 1; j < len(c.b); j++ {
					s := m.findBlice(c.b[j:])
					if s != nil && s.output {
						c.suffix = s
						break
					}
				}
			}
		}
	}

	for i := 0; i < m.extent; i++ {
		for c := 0; c < maxchar; c++ {
			n := &m.trie[i]
			for n.child[c] == nil && !n.root {
				n = n.fail
			}

			m.trie[i].fails[c] = n
		}
	}

	m.trie = m.trie[:m.extent]
	return nil
}

// Compile creates a new Matcher using a list of []byte
func Compile(dictionary [][]byte) (*Matcher, error) {
	m := new(Matcher)
	if err := m.buildTrie(dictionary); err != nil {
		return nil, err
	}
	return m, nil
}

// MustCompile returns a Matcher or panics
func MustCompile(dictionary [][]byte) *Matcher {
	m, err := Compile(dictionary)
	if err != nil {
		panic(err)
	}
	return m
}

// CompileString creates a new Matcher used to match against a set
// of strings (this is a helper to make initialization easy)
func CompileString(dictionary []string) (*Matcher, error) {
	m := new(Matcher)
	if err := m.buildTrieString(dictionary); err != nil {
		return nil, err
	}	
	return m, nil
}

// MustCompileString returns a Matcher or panics
func MustCompileString(dictionary []string) *Matcher {
	m, err := CompileString(dictionary)
	if err != nil {
		panic(err)
	}
	return m
}

// FindAll searches in for blices and returns all the blices found
// in the original dictionary
func (m *Matcher) FindAll(in []byte) [][]byte {
	m.counter++
	var hits [][]byte

	n := m.root

	for idx, b := range in {
		c := int(b)
		if c >= maxchar {
			c = 0
		}
		if !n.root && n.child[c] == nil {
			n = n.fails[c]
		}

		if n.child[c] != nil {
			f := n.child[c]
			n = f

			if f.output && f.counter != m.counter {
				hits = append(hits, in[idx-f.index+1:idx+1])
				f.counter = m.counter
			}

			for !f.suffix.root {
				f = f.suffix
				if f.counter != m.counter {
					hits = append(hits, in[idx-f.index+1:idx+1])
					f.counter = m.counter
				} else {
					// There's no point working our way up the
					// suffixes if it's been done before for this call
					// to Match. The matches are already in hits.
					break
				}
			}
		}
	}

	return hits
}

// FindAllString searches in for blices and returns all the blices (as strings) found as
// in the original dictionary
func (m *Matcher) FindAllString(in string) []string {
	m.counter++
	var hits []string

	n := m.root
	slen := len(in)
	for idx := 0; idx < slen; idx++ {
		c := int(in[idx])
		if c >= maxchar {
			c = 0
		}
		if !n.root && n.child[c] == nil {
			n = n.fails[c]
		}

		if n.child[c] != nil {
			f := n.child[c]
			n = f

			if f.output && f.counter != m.counter {
				hits = append(hits, in[idx-f.index+1:idx+1])
				f.counter = m.counter
			}

			for !f.suffix.root {
				f = f.suffix
				if f.counter != m.counter {
					hits = append(hits, in[idx-f.index+1:idx+1])
					f.counter = m.counter
				} else {
					// There's no point working our way up the
					// suffixes if it's been done before for this call
					// to Match. The matches are already in hits.
					break
				}
			}
		}
	}

	return hits
}

// Match returns true if the input slice contains any subslices
func (m *Matcher) Match(in []byte) bool {
	n := m.root
	for _, b := range in {
		c := int(b)
		if c > maxchar {
		   c = 0	
		}
		if !n.root && n.child[c] == nil {
			n = n.fails[c]
		}

		if n.child[c] != nil {
			n = n.child[c]

			if n.output {
				return true
			}

			for !n.suffix.root {
				return true
			}
		}
	}
	return false
}

// MatchString returns true if the input slice contains any subslices
func (m *Matcher) MatchString(in string) bool {
	n := m.root
	slen := len(in)
	for idx := 0; idx < slen; idx++ {
		c := int(in[idx])
		if c >= maxchar {
			c = 0	
		}
		if !n.root && n.child[c] == nil {
			n = n.fails[c]
		}
		if n.child[c] != nil {
			n = n.child[c]

			if n.output {
				return true
			}

			for !n.suffix.root {
				return true
			}
		}
	}
	return false
}
