package lexer

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// itemType identifies the type of lex items.
type ItemType int

const (
	ItemError ItemType = iota // error occurred;
	// value is text of error
	ItemEOF
	ItemAccessor // access field
	ItemIndex    // index of list
	ItemSentinel // something like base64 decode
)

const eof rune = -1

// item represents a token returned from the scanner.
type Item struct {
	Typ ItemType // Type, such as itemNumber.
	Val string   // Value, such as "23.2".
}

func (i Item) String() string {
	switch i.Typ {
	case ItemEOF:
		return "EOF"
	case ItemError:
		return i.Val
	}
	if len(i.Val) > 10 {
		return fmt.Sprintf("%.10q...", i.Val)
	}
	return fmt.Sprintf("%q", i.Val)
}

// stateFn represents the state of the scanner
// as a function that returns the next state.
type stateFn func(*Lexer) stateFn

// lexer holds the state of the scanner.
type Lexer struct {
	name  string    // used only for error reports.
	input string    // the string being scanned.
	start int       // start position of this item.
	pos   int       // current position in the input.
	width int       // width of last rune read from input.
	items chan Item // channel of scanned items.
	state stateFn
}

// lex creates a new scanner for the input string.
func Lex(name, input string) *Lexer {
	l := &Lexer{
		name:  name,
		input: input,
		state: lexExpression,
		items: make(chan Item, 2), // Two items sufficient.
	}
	return l
}

// emit passes an item back to the client.
func (l *Lexer) emit(t ItemType) {
	l.items <- Item{t, l.input[l.start:l.pos]}
	l.start = l.pos
}

// NextItem returns the next item from the input.
func (l *Lexer) NextItem() Item {
	for {
		select {
		case item := <-l.items:
			return item
		default:
			l.state = l.state(l)
		}
	}
	panic("not reached")
}

// next returns the next rune in the input.
func (l *Lexer) next() (r rune) {
	if l.pos >= len(l.input) {
		l.width = 0
		return eof
	}
	r, l.width = utf8.DecodeRuneInString(l.input[l.pos:])
	l.pos += l.width
	return r
}

// ignore skips over the pending input before this point.
func (l *Lexer) ignore() {
	l.start = l.pos
}

// backup steps back one rune.
// Can be called only once per call of next.
func (l *Lexer) backup() {
	l.pos -= l.width
}

// peek returns but does not consume
// the next rune in the input.
func (l *Lexer) peek() rune {
	rune := l.next()
	l.backup()
	return rune
}

// accept consumes the next rune
// if it's from the valid set.
func (l *Lexer) accept(valid string) bool {
	if strings.IndexRune(valid, l.next()) >= 0 {
		return true
	}
	l.backup()
	return false
}

// acceptRun consumes a run of runes from the valid set.
func (l *Lexer) acceptRun(valid string) {
	for strings.IndexRune(valid, l.next()) >= 0 {
	}
	l.backup()
}

func lexNumber(l *Lexer) stateFn {
	// Is it hex?
	digits := "0123456789"
	l.acceptRun(digits)
	// Next thing mustn't be alphanumeric.
	if l.peek() != ']' {
		l.next()
		return l.errorf("bad number syntax: %q", l.input[l.start:l.pos])
	}
	l.emit(ItemIndex)
	return lexRightBracket
}

// error returns an error token and terminates the scan
// by passing back a nil pointer that will be the next
// state, terminating l.run.
func (l *Lexer) errorf(format string, args ...interface{}) stateFn {
	l.items <- Item{
		ItemError,
		fmt.Sprintf(format, args...),
	}
	return nil
}

func lexExpression(l *Lexer) stateFn {
	for {
		switch r := l.next(); {
		case r == eof:
			l.emit(ItemEOF) // Useful to make EOF a token.
			return nil
		case unicode.IsSpace(r):
			l.ignore()
		case r == '.':
			l.ignore()
			return lexIdentifier
		case r == '[':
			l.ignore()
			return lexInsideBrackets
		case r == '|':
			l.ignore()
			return lexExpression
		default:
			return lexSentinel
		}
	}
	return nil // Stop the run loop.
}

func lexInsideBrackets(l *Lexer) stateFn {
	// Either number or quoted string
	for {
		switch r := l.next(); {
		case '0' <= r && r <= '9':
			l.backup()
			return lexNumber
		case r == '"':
			l.backup()
			return lexQuotedString
		default:
			return l.errorf("unexpected bracket: %s", string(r))
		}
	}
	panic("not reached")
}

func lexRightBracket(l *Lexer) stateFn {
	r := l.next()
	if r != ']' {
		return l.errorf("%s should be ']'", string(r))
	}
	l.ignore()
	return lexExpression
}

func lexQuotedString(l *Lexer) stateFn {
	r := l.next()
	if r != '"' {
		return l.errorf(`%s should be '"'`, string(r))
	}

	l.ignore() // drop open quote

	for isString(l.next()) {
	}
	l.backup()

	if l.peek() != '"' {
		l.next()
		return l.errorf("bad string: %q", l.input[l.start:l.pos])
	}
	l.emit(ItemAccessor)

	// consume right quote
	l.next()
	l.ignore()

	return lexRightBracket
}

func lexIdentifier(l *Lexer) stateFn {
	if l.peek() == '[' {
		l.next()
		return lexInsideBrackets
	}
	for isIdentifier(l.next()) {
	}
	l.backup()

	l.emit(ItemAccessor)
	return lexExpression
}

func lexPipe(l *Lexer) stateFn {
	for isSentinel(l.next()) {
	}
	l.backup()

	l.emit(ItemSentinel)
	return lexExpression
}

func lexSentinel(l *Lexer) stateFn {
	for isSentinel(l.next()) {
	}
	l.backup()

	l.emit(ItemSentinel)
	return lexExpression
}

func isAlphanumeric(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r)
}

func isIdentifier(r rune) bool {
	return isAlphanumeric(r) || r == '_' || r == '-'
}

func isString(r rune) bool {
	return r != eof && r != '"'
}

func isSentinel(r rune) bool {
	return r != eof && r != '|'
}
