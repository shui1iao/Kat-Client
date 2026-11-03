package clientcore

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Resource maintenance replaces only existing scalar tokens. Unlike an import,
// it must not re-encode unrelated source, comments, key order or scalar spelling.
type resourceScalarPatch struct {
	path      []string
	old, next any
}
type resourceTextEdit struct {
	start, end int
	text       string
}

func patchResourceSource(base document, changes []resourceScalarPatch) (string, error) {
	var doc yaml.Node
	if yaml.Unmarshal([]byte(base.text), &doc) != nil || len(doc.Content) != 1 {
		return "", errors.New("invalid resource source")
	}
	edits := []resourceTextEdit{}
	for _, change := range changes {
		node := doc.Content[0]
		for _, part := range change.path {
			switch node.Kind {
			case yaml.MappingNode:
				var found *yaml.Node
				for i := 0; i < len(node.Content); i += 2 {
					if node.Content[i].Value == part {
						if found != nil {
							return "", errors.New("ambiguous resource field")
						}
						found = node.Content[i+1]
					}
				}
				node = found
			case yaml.SequenceNode:
				index, err := strconv.Atoi(part)
				if err != nil || index < 0 || index >= len(node.Content) {
					return "", errors.New("missing resource item")
				}
				node = node.Content[index]
			default:
				return "", errors.New("nonliteral resource field")
			}
			if node == nil {
				return "", errors.New("missing resource field")
			}
		}
		var actual any
		if node.Kind != yaml.ScalarNode || node.Anchor != "" || node.Style&(yaml.LiteralStyle|yaml.FoldedStyle|yaml.TaggedStyle) != 0 || node.Decode(&actual) != nil || !sameResourceScalar(actual, change.old) {
			return "", errors.New("resource field changed")
		}
		start := 0
		for line := 1; line < node.Line; line++ {
			n := strings.IndexByte(base.text[start:], '\n')
			if n < 0 {
				return "", errors.New("resource position")
			}
			start += n + 1
		}
		for col := 1; col < node.Column; col++ {
			_, n := utf8.DecodeRuneInString(base.text[start:])
			if n == 0 {
				return "", errors.New("resource position")
			}
			start += n
		}
		end, err := resourceScalarEnd(base.text, start, node)
		if err != nil {
			return "", err
		}
		next, err := json.Marshal(change.next)
		if err != nil {
			return "", err
		}
		edits = append(edits, resourceTextEdit{start, end, string(next)})
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	text := base.text
	last := len(text)
	for _, edit := range edits {
		if edit.end > last {
			return "", errors.New("overlapping resource fields")
		}
		text = text[:edit.start] + edit.text + text[edit.end:]
		last = edit.start
	}
	// Verify the resulting document means precisely the requested leaf edits.
	before, err := sourceJSON(base)
	if err != nil {
		return "", err
	}
	var expected any
	if json.Unmarshal(rawJSON(before), &expected) != nil {
		return "", errors.New("resource projection")
	}
	for _, change := range changes {
		if err = replaceResourceScalar(expected, change.path, change.next); err != nil {
			return "", err
		}
	}
	after, err := sourceJSON(document{text: text, format: base.format})
	if err != nil {
		return "", err
	}
	if !sameJSON(rawJSON(expected), rawJSON(after)) {
		return "", errors.New("resource patch mismatch")
	}
	return text, nil
}
func sameResourceScalar(a, b any) bool { return sameJSON(rawJSON(a), rawJSON(b)) }
func replaceResourceScalar(value any, path []string, next any) error {
	if len(path) == 0 {
		return errors.New("empty resource field")
	}
	for _, part := range path[:len(path)-1] {
		switch x := value.(type) {
		case map[string]any:
			value = x[part]
		case []any:
			i, e := strconv.Atoi(part)
			if e != nil || i < 0 || i >= len(x) {
				return errors.New("resource item")
			}
			value = x[i]
		default:
			return errors.New("resource field")
		}
	}
	key := path[len(path)-1]
	if x, ok := value.(map[string]any); ok {
		if _, ok = x[key]; !ok {
			return errors.New("resource field")
		}
		x[key] = next
		return nil
	}
	return errors.New("resource parent")
}
func resourceScalarEnd(text string, start int, node *yaml.Node) (int, error) {
	if start < 0 || start >= len(text) {
		return 0, errors.New("resource position")
	}
	quote := text[start]
	if quote == '\'' || quote == '"' {
		for i := start + 1; i < len(text); i++ {
			if text[i] == '\n' || text[i] == '\r' {
				break
			}
			if quote == '"' && text[i] == '\\' {
				i++
				continue
			}
			if text[i] == quote {
				if quote == '\'' && i+1 < len(text) && text[i+1] == '\'' {
					i++
					continue
				}
				return i + 1, nil
			}
		}
		return 0, errors.New("multiline resource scalar")
	}
	end := start + len(node.Value)
	if end > len(text) || text[start:end] != node.Value {
		return 0, errors.New("nonliteral resource scalar")
	}
	if end < len(text) && !strings.ContainsRune(" \t\r\n,]}#", rune(text[end])) {
		return 0, errors.New("resource scalar boundary")
	}
	var parsed yaml.Node
	if yaml.Unmarshal([]byte(text[start:end]), &parsed) != nil || len(parsed.Content) != 1 {
		return 0, errors.New("resource scalar")
	}
	var a, b any
	if parsed.Content[0].Decode(&a) != nil || node.Decode(&b) != nil || !reflect.DeepEqual(a, b) {
		return 0, errors.New("resource scalar")
	}
	return end, nil
}
